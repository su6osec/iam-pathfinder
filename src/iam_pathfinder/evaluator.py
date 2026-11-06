"""Policy evaluation: turn an account export into per-principal permissions.

This module is deliberately isolated and heavily unit-tested because every
detection rule depends on it.  It implements a documented *approximation* of
AWS's policy evaluation logic (see docs/ARCHITECTURE.md):

* ``Action``/``NotAction`` and ``Resource``/``NotResource`` are matched with
  IAM-style wildcards (``*`` and ``?``), case-insensitively.
* An unconditional ``Deny`` suppresses a matching ``Allow`` only when it
  covers the same action *and* the same resource as the query.  When a rule
  queries without a resource (``ANY_RESOURCE``), only a deny that covers the
  wildcard resource ``*`` suppresses; a narrower deny is reported as
  ``partial_denies`` instead, so a risk is never hidden behind an
  unevaluatable deny.
* A ``Condition`` cannot be evaluated offline (its keys reference runtime
  context such as source IP).  Allows with a condition still match, but the
  caller must mark the result ``conditional`` and lower confidence.  Denies
  with a condition are ignored entirely: we cannot prove they apply, so we
  never let them hide a finding.
* ``Statement``-level facts (e.g. "is this ``Action: *`` on ``Resource: *``")
  are answered directly on the statement where precision matters.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .model import Account, Statement

# Sentinel meaning "the resource dimension is not part of this query".
ANY_RESOURCE: str | None = None

# --- Wildcard matching -----------------------------------------------------

_WILDCARD_CACHE: dict[str, re.Pattern[str]] = {}


def _compile(pattern: str) -> re.Pattern[str]:
    compiled = _WILDCARD_CACHE.get(pattern)
    if compiled is None:
        # IAM wildcards: '*' matches any number of characters, '?' any single
        # character.  Escape everything else, then re-introduce the wildcards.
        regex = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
        compiled = re.compile(regex, re.IGNORECASE)
        _WILDCARD_CACHE[pattern] = compiled
    return compiled


def pattern_matches(pattern: str, value: str) -> bool:
    """True when an IAM wildcard ``pattern`` covers the literal ``value``."""
    return _compile(pattern).fullmatch(value) is not None


def patterns_overlap(left: str, right: str) -> bool:
    """Conservative approximation of "these two patterns share any resource".

    True when either pattern (treated as a literal string) matches the other,
    or when either is the universal ``*``.  Patterns that overlap only in
    complex wildcard arrangements may be reported as non-overlapping; rules
    that use this never claim more than "some role in scope".
    """
    if left == "*" or right == "*":
        return True
    return pattern_matches(left, right) or pattern_matches(right, left)


def resources_overlap(left: tuple[str, ...], right: tuple[str, ...]) -> bool:
    """True when any pattern in ``left`` overlaps any pattern in ``right``."""
    return any(patterns_overlap(a, b) for a in left for b in right)


# --- Statement matching ----------------------------------------------------


def action_covers(stmt: Statement, action: str) -> bool:
    """True when the statement's action scope includes the concrete ``action``.

    ``Action`` takes precedence if both fields are present (AWS rejects that,
    but a malformed export should not crash the tool).
    """
    if stmt.actions:
        return any(pattern_matches(p, action) for p in stmt.actions)
    if stmt.not_actions:
        # NotAction grants everything *except* the listed actions.
        return not any(pattern_matches(p, action) for p in stmt.not_actions)
    return False


def resource_covers(stmt: Statement, resource: str) -> bool:
    """True when the statement's resource scope includes ``resource``.

    ``resource`` may be a concrete ARN or the literal wildcard ``*``.
    ``*`` is only covered by a statement whose ``Resource`` contains ``*``
    with no ``NotResource`` exclusions.
    """
    if resource == "*":
        if stmt.not_resources:
            return False
        # No Resource at all: be lenient (matches the concrete-resource path).
        return "*" in stmt.resources or not stmt.resources
    if stmt.resources:
        if not any(pattern_matches(p, resource) for p in stmt.resources):
            return False
    if stmt.not_resources:
        if any(pattern_matches(p, resource) for p in stmt.not_resources):
            return False
    # No Resource/NotResource at all: be lenient and treat as covering.
    return True


def is_universal_allow(stmt: Statement) -> bool:
    """Literal ``Action: *`` on ``Resource: *`` with no exclusions."""
    return (
        stmt.is_allow
        and not stmt.is_conditional
        and "*" in stmt.actions
        and "*" in stmt.resources
        and not stmt.not_actions
        and not stmt.not_resources
    )


def is_universal_deny(stmt: Statement) -> bool:
    """A deny that removes everything: covers action ``*`` on resource ``*``."""
    return (
        stmt.is_deny
        and not stmt.is_conditional
        and action_covers(stmt, "*")
        and resource_covers(stmt, "*")
    )


# --- Statement references --------------------------------------------------


@dataclass(frozen=True)
class StatementRef:
    """A statement plus where it came from (for findings' evidence)."""

    statement: Statement
    policy_name: str
    policy_arn: str | None = None
    origin: str = "inline"  # "inline" | "managed"
    via_group: str | None = None  # group name when inherited

    @property
    def source_label(self) -> str:
        kind = "inline" if self.origin == "inline" else "managed"
        label = f'{kind} policy "{self.policy_name}"'
        if self.via_group:
            return f'group "{self.via_group}" {label}'
        return label


@dataclass
class PermissionQuery:
    """Result of asking "does this principal have permission P?" """

    status: str  # "allowed" | "denied" | "not_allowed"
    allows: list[StatementRef] = field(default_factory=list)
    denies: list[StatementRef] = field(default_factory=list)
    partial_denies: list[StatementRef] = field(default_factory=list)

    @property
    def allowed(self) -> bool:
        return self.status == "allowed"

    @property
    def conditional(self) -> bool:
        """True when every matching allow depends on a Condition."""
        return bool(self.allows) and all(r.statement.is_conditional for r in self.allows)


# --- Effective permissions for one principal -------------------------------


class EffectivePermissions:
    """All statements that apply to one principal (user, role or group)."""

    def __init__(self, refs: list[StatementRef]) -> None:
        self.refs = refs

    @property
    def allows(self) -> list[StatementRef]:
        return [r for r in self.refs if r.statement.is_allow]

    @property
    def denies(self) -> list[StatementRef]:
        return [r for r in self.refs if r.statement.is_deny]

    def matching_allows(
        self, action: str, resource: str | None = ANY_RESOURCE
    ) -> list[StatementRef]:
        """Allow statements whose scope includes ``action`` (and ``resource``)."""
        result = []
        for ref in self.allows:
            if not action_covers(ref.statement, action):
                continue
            if resource is not None and not resource_covers(ref.statement, resource):
                continue
            result.append(ref)
        return result

    def query(self, action: str, resource: str | None = ANY_RESOURCE) -> PermissionQuery:
        """Evaluate whether the principal may perform ``action``.

        ``resource=None`` means "somewhere": any allow on the action counts
        and only a resource-universal deny suppresses.  A concrete resource
        (or ``"*"``) makes resource matching part of both allow and deny.
        """
        allows = self.matching_allows(action, resource)

        denies: list[StatementRef] = []
        partial: list[StatementRef] = []
        for ref in self.denies:
            stmt = ref.statement
            if stmt.is_conditional:
                # Cannot be evaluated offline; must never hide a finding.
                continue
            if not action_covers(stmt, action):
                continue
            if resource is None:
                if resource_covers(stmt, "*"):
                    denies.append(ref)
                else:
                    partial.append(ref)
            elif resource_covers(stmt, resource):
                denies.append(ref)

        if denies:
            return PermissionQuery(
                status="denied", allows=[], denies=denies, partial_denies=partial
            )
        if allows:
            return PermissionQuery(
                status="allowed", allows=allows, denies=[], partial_denies=partial
            )
        return PermissionQuery(status="not_allowed")

    def is_full_admin(self) -> bool:
        """True for a standing, unconditional ``Action: *`` on ``Resource: *``.

        A conditional universal allow does not count (it is not standing
        admin), and an unconditional deny covering action+resource ``*``
        negates it (e.g. ``Deny NotAction: iam:*`` on ``*``).
        """
        if not any(is_universal_allow(r.statement) for r in self.refs):
            return False
        return not any(is_universal_deny(r.statement) for r in self.refs)


# --- Building effective permissions for an account -------------------------


def _ref(policy_name: str, policy_arn: str | None, statement: Statement, *, origin: str,
          via_group: str | None = None) -> StatementRef:
    return StatementRef(
        statement=statement,
        policy_name=policy_name,
        policy_arn=policy_arn,
        origin=origin,
        via_group=via_group,
    )


def _policy_refs(account: Account, refs: list[tuple[str, str]]) -> list[StatementRef]:
    """Resolve (name, arn) attachment pairs to statements.

    Attachments that do not resolve to a document in the export are skipped;
    the parser reports them separately so callers can warn.
    """
    out: list[StatementRef] = []
    for _name, arn in refs:
        doc = account.resolve_policy(arn)
        if doc is None:
            continue
        out.extend(_ref(doc.name, arn, s, origin="managed") for s in doc.statements)
    return out


def _inline_refs(inline_policies: list, *, origin: str = "inline") -> list[StatementRef]:
    out: list[StatementRef] = []
    for doc in inline_policies:
        out.extend(_ref(doc.name, None, s, origin=origin) for s in doc.statements)
    return out


def build_effective_permissions(account: Account) -> dict[str, EffectivePermissions]:
    """Build effective statements for every principal.

    Keys are ``"user:name"``, ``"role:name"`` and ``"group:name"``.
    Group inheritance: a user's permissions include their groups' inline and
    attached managed policies.  Role trust policies are *not* part of a
    role's permissions (they control who can assume the role).
    """
    effective: dict[str, EffectivePermissions] = {}

    for name, group in account.groups.items():
        refs = _inline_refs(group.inline_policies) + _policy_refs(
            account, group.attached_policy_refs
        )
        effective[f"group:{name}"] = EffectivePermissions(refs)

    for name, user in account.users.items():
        refs = _inline_refs(user.inline_policies) + _policy_refs(account, user.attached_policy_refs)
        for group_name in user.group_names:
            group_key = f"group:{group_name}"
            group_eff = effective.get(group_key)
            if group_eff is None:
                continue  # user references a group missing from the export
            for ref in group_eff.refs:
                refs.append(
                    StatementRef(
                        statement=ref.statement,
                        policy_name=ref.policy_name,
                        policy_arn=ref.policy_arn,
                        origin=ref.origin,
                        via_group=group_name,
                    )
                )
        effective[f"user:{name}"] = EffectivePermissions(refs)

    for name, role in account.roles.items():
        refs = _inline_refs(role.inline_policies) + _policy_refs(account, role.attached_policy_refs)
        effective[f"role:{name}"] = EffectivePermissions(refs)

    return effective
