"""Core data model for an exported AWS IAM configuration.

Everything here is a plain, serializable description of the JSON returned by
``aws iam get-account-authorization-details``.  No AWS SDK is used anywhere in
this package: the tool is designed to run on a local file only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

# --- IAM policy primitives -------------------------------------------------

ALLOW = "Allow"
DENY = "Deny"


@dataclass
class Statement:
    """One statement of an IAM policy document.

    ``Action``/``NotAction`` and ``Resource``/``NotResource`` are normalised
    into tuples so the evaluator never has to care whether the original JSON
    used a string or a list.  The untouched original statement is kept in
    ``raw`` so findings can quote exactly what triggered them.
    """

    effect: str
    actions: tuple[str, ...] = ()
    not_actions: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    not_resources: tuple[str, ...] = ()
    condition: dict[str, Any] | None = None
    sid: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_allow(self) -> bool:
        return self.effect == ALLOW

    @property
    def is_deny(self) -> bool:
        return self.effect == DENY

    @property
    def is_conditional(self) -> bool:
        """True when the statement only applies if a Condition holds."""
        return bool(self.condition)


def _as_tuple(value: Any) -> tuple[str, ...]:
    """Normalise a policy string-or-list field to a tuple of strings."""
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, list):
        return tuple(str(item) for item in value)
    return (str(value),)


def statement_from_dict(data: dict[str, Any]) -> Statement:
    """Build a :class:`Statement` from a raw policy statement mapping."""
    return Statement(
        effect=str(data.get("Effect", ALLOW)),
        actions=_as_tuple(data.get("Action")),
        not_actions=_as_tuple(data.get("NotAction")),
        resources=_as_tuple(data.get("Resource")),
        not_resources=_as_tuple(data.get("NotResource")),
        condition=data.get("Condition"),
        sid=data.get("Sid"),
        raw=dict(data),
    )


@dataclass
class PolicyDocument:
    """A policy document (managed or inline) with its parsed statements."""

    name: str
    statements: list[Statement]
    arn: str | None = None  # None for inline policies
    version_id: str | None = None  # default version, for managed policies

    @property
    def is_inline(self) -> bool:
        return self.arn is None


# --- IAM entities ----------------------------------------------------------


@dataclass
class User:
    name: str
    arn: str
    user_id: str | None = None
    group_names: tuple[str, ...] = ()
    inline_policies: list[PolicyDocument] = field(default_factory=list)
    # (policy name, policy arn) pairs as attached in the export; documents are
    # resolved against the account's managed policies after parsing.
    attached_policy_refs: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class Group:
    name: str
    arn: str
    group_id: str | None = None
    inline_policies: list[PolicyDocument] = field(default_factory=list)
    attached_policy_refs: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class Role:
    name: str
    arn: str
    role_id: str | None = None
    trust_policy: PolicyDocument | None = None
    inline_policies: list[PolicyDocument] = field(default_factory=list)
    attached_policy_refs: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class ManagedPolicy:
    """A managed policy and *all* of its versions from the export."""

    name: str
    arn: str
    default_version_id: str | None = None
    versions: dict[str, PolicyDocument] = field(default_factory=dict)

    @property
    def default_version(self) -> PolicyDocument | None:
        if self.default_version_id and self.default_version_id in self.versions:
            return self.versions[self.default_version_id]
        # Fall back to the version flagged IsDefaultVersion, then to any version.
        for doc in self.versions.values():
            if doc.version_id == self.default_version_id:
                return doc
        return next(iter(self.versions.values()), None)


@dataclass
class Account:
    """The whole exported account configuration."""

    users: dict[str, User] = field(default_factory=dict)
    groups: dict[str, Group] = field(default_factory=dict)
    roles: dict[str, Role] = field(default_factory=dict)
    managed_policies: dict[str, ManagedPolicy] = field(default_factory=dict)
    account_id: str | None = None

    def resolve_policy(self, arn: str) -> PolicyDocument | None:
        """Return the default version of a managed policy by ARN, if present."""
        policy = self.managed_policies.get(arn)
        return policy.default_version if policy else None
