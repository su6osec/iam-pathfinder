"""Tests for the privilege-escalation graph (nodes, edges, multi-hop paths)."""

from __future__ import annotations

from conftest import export, policy_document, role, role_arn, stmt, user, user_arn

from iam_pathfinder.analyzer import analyze_account
from iam_pathfinder.graph import (
    DEFAULT_MAX_DEPTH,
    VIRTUAL_ADMIN,
    build_graph,
    find_paths,
)
from iam_pathfinder.parser import parse_export


def _graph(data: dict):
    account = parse_export(data).account
    _ctx, findings = analyze_account(account)
    return findings, build_graph(_ctx, findings)


def _trust_for(*principals: str) -> dict:
    return policy_document(
        stmt("Allow", Principal={"AWS": list(principals)}, Resource="*")
    )


def _assume_policy() -> list[tuple[str, dict]]:
    return [
        (
            "AssumeAnything",
            policy_document(stmt("Allow", action="sts:AssumeRole", resource="*")),
        )
    ]


def _admin_policy() -> list[tuple[str, dict]]:
    return [("Admin", policy_document(stmt("Allow", action="*", resource="*")))]


class TestNodesAndEdges:
    def test_nodes_include_users_roles_and_virtual_admin(self):
        data = export(
            users=[user("alice")],
            roles=[role("deploy", trust=_trust_for(user_arn("alice")))],
        )
        _findings, graph = _graph(data)
        assert set(graph.nodes) == {"user:alice", "role:deploy", VIRTUAL_ADMIN}
        assert graph.nodes[VIRTUAL_ADMIN].kind == "virtual"

    def test_assume_edge_requires_permission_and_trust(self):
        data = export(
            users=[user("alice", inline=_assume_policy())],
            roles=[
                role("open", trust=_trust_for(user_arn("alice"))),
                role("closed", trust=_trust_for(user_arn("somebody-else"))),
            ],
        )
        _findings, graph = _graph(data)
        edges = {(e.source, e.target, e.kind) for e in graph.edges}
        assert ("user:alice", "role:open", "assume") in edges
        assert ("user:alice", "role:closed", "assume") not in edges

    def test_assume_edge_requires_permission(self):
        data = export(
            users=[user("alice")],  # no sts:AssumeRole at all
            roles=[role("open", trust=_trust_for(user_arn("alice")))],
        )
        _findings, graph = _graph(data)
        assert [e for e in graph.edges if e.kind == "assume"] == []

    def test_escalate_edge_comes_from_a_finding(self):
        data = export(
            users=[
                user(
                    "alice",
                    inline=[
                        (
                            "Escalate",
                            policy_document(
                                stmt(
                                    "Allow",
                                    action="iam:CreatePolicyVersion",
                                    resource="*",
                                )
                            ),
                        )
                    ],
                )
            ],
        )
        findings, graph = _graph(data)
        assert any(f.rule_id == "IAM_CREATE_POLICY_VERSION" for f in findings)
        edges = [(e.source, e.target, e.rule_id) for e in graph.edges if e.kind == "escalate"]
        assert edges == [("user:alice", VIRTUAL_ADMIN, "IAM_CREATE_POLICY_VERSION")]

    def test_group_privileges_do_not_create_user_edges_without_membership(self):
        # A group's permissions are inherited by its members; a non-member
        # user must not receive an escalate edge.
        from conftest import group

        data = export(
            groups=[
                group(
                    "admins",
                    inline=[
                        (
                            "Admin",
                            policy_document(stmt("Allow", action="*", resource="*")),
                        )
                    ],
                )
            ],
            users=[user("alice"), user("bob", groups=["admins"])],
        )
        findings, graph = _graph(data)
        escalate_sources = {e.source for e in graph.edges if e.kind == "escalate"}
        assert escalate_sources == {"user:bob"}
        assert any(f.rule_id == "FULL_ADMIN" for f in findings)


class TestPaths:
    def test_two_hop_path_through_assumable_admin_role(self):
        data = export(
            users=[user("alice", inline=_assume_policy())],
            roles=[role("admin", trust=_trust_for(user_arn("alice")), inline=_admin_policy())],
        )
        findings, graph = _graph(data)
        assert any(f.rule_id == "FULL_ADMIN" for f in findings)
        paths = find_paths(graph, starts=["user:alice"])
        assert len(paths) == 1
        path = paths[0]
        assert path.start == "user:alice"
        assert path.length == 2
        assert [s.kind for s in path.steps] == ["assume", "escalate"]
        assert path.steps[0].target == "role:admin"
        assert path.end == VIRTUAL_ADMIN

    def test_default_starts_include_roles_too(self):
        data = export(
            users=[user("alice")],
            roles=[role("admin", trust=_trust_for(user_arn("alice")), inline=_admin_policy())],
        )
        _findings, graph = _graph(data)
        starts = {p.start for p in find_paths(graph)}
        assert starts == {"role:admin"}

    def test_three_hop_path(self):
        data = export(
            users=[user("alice", inline=_assume_policy())],
            roles=[
                role("jump", trust=_trust_for(user_arn("alice")), inline=_assume_policy()),
                role(
                    "inner",
                    trust=_trust_for(role_arn("jump")),
                    inline=_admin_policy(),
                ),
            ],
        )
        _findings, graph = _graph(data)
        paths = find_paths(graph, starts=["user:alice"])
        assert [p.length for p in paths] == [3]
        assert [s.target for s in paths[0].steps] == [
            "role:jump",
            "role:inner",
            VIRTUAL_ADMIN,
        ]

    def test_depth_limit_drops_long_paths(self):
        data = export(
            users=[user("alice", inline=_assume_policy())],
            roles=[
                role("jump", trust=_trust_for(user_arn("alice")), inline=_assume_policy()),
                role("inner", trust=_trust_for(role_arn("jump")), inline=_admin_policy()),
            ],
        )
        _findings, graph = _graph(data)
        assert find_paths(graph, max_depth=2, starts=["user:alice"]) == []
        assert len(find_paths(graph, max_depth=3, starts=["user:alice"])) == 1
        assert DEFAULT_MAX_DEPTH >= 3

    def test_cycle_is_not_revisited(self):
        data = export(
            users=[user("alice", inline=_assume_policy())],
            roles=[
                role(
                    "left",
                    trust=_trust_for(role_arn("right"), user_arn("alice")),
                    inline=_assume_policy() + _admin_policy(),
                ),
                role(
                    "right",
                    trust=_trust_for(role_arn("left")),
                    inline=_assume_policy(),
                ),
            ],
        )
        _findings, graph = _graph(data)
        paths = find_paths(graph)  # must terminate and never loop
        assert paths, "expected at least the alice -> left -> admin path"
        for path in paths:
            nodes = [path.start] + [s.target for s in path.steps]
            assert len(nodes) == len(set(nodes)), path.describe()
        assert min(p.length for p in paths if p.start == "user:alice") == 2
        assert all(p.length <= DEFAULT_MAX_DEPTH for p in paths)

    def test_roles_without_a_path_are_not_reported(self):
        data = export(
            users=[user("alice")],
            roles=[role("harmless", trust=_trust_for(user_arn("alice")))],
        )
        _findings, graph = _graph(data)
        assert find_paths(graph) == []

    def test_paths_are_deterministically_sorted(self):
        data = export(
            users=[user("alice", inline=_assume_policy())],
            roles=[
                role("a_admin", trust=_trust_for(user_arn("alice")), inline=_admin_policy()),
                role("b_admin", trust=_trust_for(user_arn("alice")), inline=_admin_policy()),
            ],
        )
        _findings, graph = _graph(data)
        first = find_paths(graph)
        second = find_paths(graph)
        assert [p.describe() for p in first] == [p.describe() for p in second]
        lengths = [p.length for p in first]
        assert lengths == sorted(lengths)
