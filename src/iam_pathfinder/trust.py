"""Role trust-policy helpers.

A role's trust policy (``AssumeRolePolicyDocument``) decides *who* may assume
the role; it is not part of the role's own permissions.  These helpers answer
two questions used by both detection rules and the escalation graph:

* does this trust policy admit a given principal (directly, via the account
  root, or publicly via ``"*"``)?
* which raw facts do hygiene rules need (public principal, cross-account
  principal, account-root principal, ``sts:ExternalId`` condition)?

Only ``Effect: Allow`` statements are considered: in practice trust policies
are Allow-only, and AWS ignores Deny statements inside them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from .model import Role, Statement

_ACCOUNT_ID_RE = re.compile(r"^\d{12}$")
_ROOT_ARN_RE = re.compile(r"^arn:aws[a-z-]*:iam::(\d{12}):root$")


@dataclass
class TrustMatch:
    """Whether a role's trust policy admits a principal."""

    allowed: bool = False
    conditional: bool = False  # matched statement(s) carry a Condition
    public: bool = False  # matched via Principal "*"
    via_root: bool = False  # matched via same-account (or external) root


def principal_account_id(principal_arn: str) -> str | None:
    """Account id embedded in an IAM principal ARN, if any."""
    match = _ROOT_ARN_RE.match(principal_arn) or re.match(
        r"^arn:aws[a-z-]*:iam::(\d{12}):", principal_arn
    )
    return match.group(1) if match else None


def _aws_entries(principal: Any) -> list[str]:
    """Normalise the ``AWS`` field of a Principal block to a list of strings."""
    if not isinstance(principal, dict):
        return []
    value = principal.get("AWS")
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return []


def is_public_principal(stmt: Statement) -> bool:
    """True for ``Principal: "*"`` or ``Principal: {"AWS": "*"}``."""
    principal = stmt.raw.get("Principal")
    if principal == "*":
        return True
    return any(entry == "*" for entry in _aws_entries(principal))


def aws_principal_entries(stmt: Statement) -> list[str]:
    """All ``AWS`` principal entries of a trust statement (may be empty)."""
    return _aws_entries(stmt.raw.get("Principal"))


def account_id_of_entry(entry: str) -> str | None:
    """Account id a principal entry points at (root ARN or bare account id)."""
    match = _ROOT_ARN_RE.match(entry)
    if match:
        return match.group(1)
    if _ACCOUNT_ID_RE.match(entry):
        return entry
    return None


def has_external_id_condition(stmt: Statement) -> bool:
    """True when the statement conditions on ``sts:ExternalId``.

    Only the condition *key* is checked: values cannot be judged offline
    beyond "an external id is required", which is the protection we care
    about here.
    """
    condition = stmt.condition
    if not isinstance(condition, dict):
        return False
    for operator in condition.values():
        if isinstance(operator, dict):
            for key in operator:
                if str(key).lower() == "sts:externalid":
                    return True
    return False


def _entry_matches(entry: str, principal_arn: str, principal_account: str | None) -> bool:
    if entry == principal_arn:
        return True
    entry_account = account_id_of_entry(entry)
    if entry_account is not None and principal_account is not None:
        # Account root (or bare account id) admits every principal *in that
        # account* that also holds sts:AssumeRole permission on the role.
        return entry_account == principal_account
    return False


def trust_allows(role: Role, principal_arn: str) -> TrustMatch:
    """Check whether ``role``'s trust policy admits ``principal_arn``.

    Approximation: conditions are not evaluated - a matched statement with a
    Condition counts as allowing but marks the match ``conditional`` so
    callers can lower confidence.
    """
    if role.trust_policy is None:
        return TrustMatch(allowed=False)

    principal_account = principal_account_id(principal_arn)
    result = TrustMatch()
    for stmt in role.trust_policy.statements:
        if not stmt.is_allow:
            continue
        principal = stmt.raw.get("Principal")
        matched = False
        if principal == "*":
            matched = True
            result.public = True
        else:
            for entry in aws_principal_entries(stmt):
                if entry == "*":
                    matched = True
                    result.public = True
                elif _entry_matches(entry, principal_arn, principal_account):
                    matched = True
                    entry_account = account_id_of_entry(entry)
                    if entry_account is not None and entry != principal_arn:
                        result.via_root = True
        if matched:
            result.allowed = True
            if stmt.is_conditional:
                result.conditional = True
    return result
