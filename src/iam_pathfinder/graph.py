"""Privilege-escalation graph: multi-hop paths from principals to ``virtual:admin``.

The graph is a first-class structure (``docs/ARCHITECTURE.md``):

* **Nodes** — one per IAM user and per IAM role, plus a virtual node
  ``virtual:admin`` representing full administrative control of the account.
* **Edges** — two kinds:
    * ``assume``: the source principal may call ``sts:AssumeRole`` on the target
      role *and* the role's trust policy accepts that principal.
    * ``escalate``: the source principal already holds capabilities that (per the
      rule catalogue) lead to full admin — an escalation *finding* is an edge.
* **Paths** — depth-first/BFS walks from any user or role to ``virtual:admin``.
  Paths longer than ``max_depth`` edges are dropped and nodes already on the
  current path are never revisited (cycle protection).

Paths are reported with the rule id and a human explanation for every step.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field

from iam_pathfinder.context import AnalysisContext
from iam_pathfinder.rules.base import Finding
from iam_pathfinder.rules.helpers import covered_values
from iam_pathfinder.trust import trust_allows

VIRTUAL_ADMIN = "virtual:admin"
DEFAULT_MAX_DEPTH = 4

#: Rule ids whose findings mean "this principal can reach full admin" and are
#: therefore modelled as an ``escalate`` edge.  Single-permission escalation
#: rules, PassRole combinations, PassRole-wildcard and the admin/hygiene rules
#: that indicate unrestricted power.
ESCALATING_RULES = frozenset(
    {
        "IAM_CREATE_POLICY_VERSION",
        "IAM_SET_DEFAULT_POLICY_VERSION",
        "IAM_ATTACH_USER_POLICY",
        "IAM_ATTACH_GROUP_POLICY",
        "IAM_ATTACH_ROLE_POLICY",
        "IAM_PUT_USER_POLICY",
        "IAM_PUT_GROUP_POLICY",
        "IAM_PUT_ROLE_POLICY",
        "IAM_ADD_USER_TO_GROUP",
        "IAM_CREATE_ACCESS_KEY",
        "IAM_LOGIN_PROFILE",
        "IAM_UPDATE_ASSUME_ROLE_POLICY",
        "PASSROLE_EC2_RUNINSTANCES",
        "PASSROLE_LAMBDA_CREATE_INVOKE",
        "PASSROLE_CLOUDFORMATION_CREATE_STACK",
        "PASSROLE_WILDCARD",
        "FULL_ADMIN",
        "SERVICE_WILDCARD",
        "BROAD_NOT_ACTION",
    }
)


@dataclass(frozen=True)
class GraphNode:
    id: str
    kind: str  # "user" | "role" | "virtual"
    label: str


@dataclass(frozen=True)
class GraphEdge:
    source: str
    target: str
    kind: str  # "assume" | "escalate"
    detail: str
    rule_id: str | None = None


@dataclass(frozen=True)
class PathStep:
    source: str
    target: str
    kind: str
    detail: str
    rule_id: str | None


@dataclass(frozen=True)
class EscalationPath:
    """A chain of edges from a principal to ``virtual:admin``."""

    start: str
    steps: tuple[PathStep, ...]

    @property
    def length(self) -> int:
        return len(self.steps)

    @property
    def end(self) -> str:
        return self.steps[-1].target if self.steps else self.start

    def describe(self) -> str:
        """Human-readable rendering, e.g. ``alice -> role:AdminRole (assume) ->
        virtual:admin (escalate: FULL_ADMIN)``."""
        parts = [self.start]
        for step in self.steps:
            arrow = "assume" if step.kind == "assume" else f"escalate:{step.rule_id or '?'}"
            parts.append(f"{arrow} {step.target}")
        return " -> ".join(parts)


@dataclass
class EscalationGraph:
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)

    def add_node(self, node: GraphNode) -> None:
        self.nodes.setdefault(node.id, node)

    def outgoing(self, node_id: str) -> list[GraphEdge]:
        return [e for e in self.edges if e.source == node_id]

    def edge_count(self) -> int:
        return len(self.edges)


def _node_id(kind: str, name: str) -> str:
    return f"{kind}:{name}"


def build_graph(ctx: AnalysisContext, findings: list[Finding]) -> EscalationGraph:
    """Build the escalation graph from the account plus its findings.

    ``findings`` are the analyzer output; only findings whose rule is in
    :data:`ESCALATING_RULES` become ``escalate`` edges.
    """
    graph = EscalationGraph()

    principals: list[tuple[str, str]] = (
        [("user", name) for name in sorted(ctx.account.users)]
        + [("role", name) for name in sorted(ctx.account.roles)]
    )
    for kind, name in principals:
        graph.add_node(GraphNode(id=_node_id(kind, name), kind=kind, label=name))
    graph.add_node(GraphNode(id=VIRTUAL_ADMIN, kind="virtual", label="Full admin"))

    for kind, name in principals:
        source = _node_id(kind, name)
        principal_arn = ctx.arn(kind, name)
        assume_query = ctx.eff(kind, name).query("sts:AssumeRole")

        # --- assume edges -------------------------------------------------
        if assume_query.allowed:
            for role_name, role in sorted(ctx.account.roles.items()):
                role_id = f"role:{role_name}"
                if role.arn == principal_arn:
                    continue
                if not covered_values(assume_query, [role.arn]):
                    continue
                if not trust_allows(role, principal_arn).allowed:
                    continue
                graph.add_node(GraphNode(id=role_id, kind="role", label=role_name))
                graph.edges.append(
                    GraphEdge(
                        source=source,
                        target=role_id,
                        kind="assume",
                        detail=(
                            f"{name} can sts:AssumeRole {role_name} "
                            f"(trust policy accepts {principal_arn})"
                        ),
                    )
                )

        # --- escalate edges (from findings) --------------------------------
        for finding in findings:
            if finding.rule_id not in ESCALATING_RULES:
                continue
            if finding.principal_type != kind or finding.principal_name != name:
                continue
            evidence = finding.evidence[0].source_label if finding.evidence else "policy"
            graph.edges.append(
                GraphEdge(
                    source=source,
                    target=VIRTUAL_ADMIN,
                    kind="escalate",
                    detail=f"{finding.title} ({evidence})",
                    rule_id=finding.rule_id,
                )
            )

    return graph


def find_paths(
    graph: EscalationGraph,
    max_depth: int = DEFAULT_MAX_DEPTH,
    starts: list[str] | None = None,
) -> list[EscalationPath]:
    """Find every path from the start nodes to ``virtual:admin``.

    * ``max_depth`` caps the number of edges in a path.
    * Cycle protection: a node already present on the path is never revisited.
    * Paths are returned sorted by length, then lexicographically, so output is
      deterministic.
    """
    if starts is None:
        starts = sorted(n.id for n in graph.nodes.values() if n.kind in {"user", "role"})

    found: list[EscalationPath] = []
    for start in starts:
        queue: deque[tuple[str, tuple[PathStep, ...], frozenset[str]]] = deque()
        queue.append((start, (), frozenset({start})))
        while queue:
            current, steps, visited = queue.popleft()
            if current == VIRTUAL_ADMIN and steps:
                found.append(EscalationPath(start=start, steps=steps))
                continue
            if len(steps) >= max_depth:
                continue
            for edge in graph.outgoing(current):
                if edge.target in visited:
                    continue
                step = PathStep(
                    source=edge.source,
                    target=edge.target,
                    kind=edge.kind,
                    detail=edge.detail,
                    rule_id=edge.rule_id,
                )
                queue.append(
                    (edge.target, steps + (step,), visited | {edge.target})
                )

    found.sort(key=lambda p: (p.length, p.describe()))
    return found
