"""Analysis context: everything a rule needs to know about the account.

Rules never touch the raw export themselves; they ask the context questions
such as "is this principal already an admin?" or "which local policies are
attached to this principal?".  This keeps rule code short and puts the
severity-context logic in one tested place.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .evaluator import EffectivePermissions, build_effective_permissions
from .model import Account

# Actions that, on their own, let a principal reach full admin (the
# single-permission escalation techniques implemented by this tool).  Used
# ONLY to judge severity context ("is this principal interesting to become?"),
# never to raise new findings.  Documented in docs/ARCHITECTURE.md.
ESCALATION_CAPABILITY_ACTIONS: tuple[str, ...] = (
    "iam:CreatePolicyVersion",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:AttachRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:PutRolePolicy",
    "iam:AddUserToGroup",
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
)


@dataclass
class AnalysisContext:
    """Parsed account plus derived, cached facts rules need."""

    account: Account
    effective: dict[str, EffectivePermissions] = field(init=False)
    _admin_cache: dict[str, bool] = field(init=False, default_factory=dict)
    _priv_cache: dict[str, bool] = field(init=False, default_factory=dict)

    def __post_init__(self) -> None:
        self.effective = build_effective_permissions(self.account)

    # --- basics ------------------------------------------------------------

    def key(self, kind: str, name: str) -> str:
        return f"{kind}:{name}"

    def eff(self, kind: str, name: str) -> EffectivePermissions:
        """Effective permissions of a principal (empty if unknown)."""
        return self.effective.get(self.key(kind, name)) or EffectivePermissions([])

    def arn(self, kind: str, name: str) -> str:
        collection = {
            "user": self.account.users,
            "role": self.account.roles,
            "group": self.account.groups,
        }[kind]
        return collection[name].arn

    def iter_principals(self, kinds: tuple[str, ...] = ("user", "role", "group")):
        """Yield ``(kind, name)`` for every principal of the wanted types."""
        collections = {
            "user": self.account.users,
            "role": self.account.roles,
            "group": self.account.groups,
        }
        for kind in kinds:
            for name in sorted(collections[kind]):
                yield kind, name

    # --- severity context ---------------------------------------------------

    def is_full_admin(self, kind: str, name: str) -> bool:
        cache_key = self.key(kind, name)
        if cache_key not in self._admin_cache:
            self._admin_cache[cache_key] = self.eff(kind, name).is_full_admin()
        return self._admin_cache[cache_key]

    def is_privileged(self, kind: str, name: str) -> bool:
        """Heuristic: full admin, or holds a single-permission escalation.

        Used only to grade severity (e.g. "PassRole is scoped to a role that
        itself holds escalation permissions"), never to create findings.
        """
        cache_key = self.key(kind, name)
        if cache_key in self._priv_cache:
            return self._priv_cache[cache_key]
        if self.is_full_admin(kind, name):
            self._priv_cache[cache_key] = True
            return True
        eff = self.eff(kind, name)
        result = any(
            eff.query(action).allowed for action in ESCALATION_CAPABILITY_ACTIONS
        )
        self._priv_cache[cache_key] = result
        return result

    def privileged_groups(self) -> list[str]:
        """Groups whose members gain admin/escalation permissions."""
        return [
            name
            for kind, name in self.iter_principals(("group",))
            if self.is_privileged(kind, name)
        ]

    def admin_users(self) -> list[str]:
        return [
            name
            for kind, name in self.iter_principals(("user",))
            if self.is_full_admin(kind, name)
        ]

    def policy_is_privileged(self, arn: str) -> bool:
        """True when a managed policy's default version grants admin/escalation.

        Used to grade severity for rules whose resource scope is a policy ARN
        (attaching such a policy to a controllable target is direct escalation).
        """
        from .evaluator import StatementRef

        doc = self.account.resolve_policy(arn)
        if doc is None:
            return False
        eff = EffectivePermissions(
            [StatementRef(s, doc.name, arn, "managed") for s in doc.statements]
        )
        if eff.is_full_admin():
            return True
        return any(eff.query(a).allowed for a in ESCALATION_CAPABILITY_ACTIONS)

    # --- policy scope helpers ----------------------------------------------

    def attached_local_policy_arns(self, kind: str, name: str) -> list[str]:
        """Local (customer-managed) managed policies attached to a principal.

        Only local policies can receive new versions; AWS-managed policies
        (``arn:aws:iam::aws:policy/...``) cannot be modified.
        """
        entity = {
            "user": self.account.users.get(name),
            "role": self.account.roles.get(name),
            "group": self.account.groups.get(name),
        }[kind]
        if entity is None:
            return []
        return [
            arn
            for _, arn in entity.attached_policy_refs
            if not arn.startswith("arn:aws:iam::aws:policy/")
        ]

    def attached_policy_arns(self, kind: str, name: str) -> list[str]:
        """All attached managed policy ARNs (local and AWS-managed)."""
        entity = {
            "user": self.account.users.get(name),
            "role": self.account.roles.get(name),
            "group": self.account.groups.get(name),
        }[kind]
        if entity is None:
            return []
        return [arn for _, arn in entity.attached_policy_refs]

    def role_names_covering(self, arns: list[str]) -> list[str]:
        """Roles whose ARN is matched by any of the given patterns."""
        from .evaluator import pattern_matches

        matched = []
        for role_name, role in sorted(self.account.roles.items()):
            if any(pattern_matches(pattern, role.arn) for pattern in arns):
                matched.append(role_name)
        return matched
