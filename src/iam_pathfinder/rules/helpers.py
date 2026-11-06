"""Helpers shared by rule modules (scope grading, evidence, confidence)."""

from __future__ import annotations

from ..context import AnalysisContext
from ..evaluator import PermissionQuery, resource_covers
from ..trust import trust_allows
from .base import (
    HIGH_CONFIDENCE,
    LOW_CONFIDENCE,
    MEDIUM_CONFIDENCE,
    Evidence,
    evidence_from_ref,
)


def confidence_for(query: PermissionQuery) -> str:
    """Confidence for a finding derived from a permission query."""
    if query.partial_denies:
        return LOW_CONFIDENCE
    if query.conditional:
        return MEDIUM_CONFIDENCE
    return HIGH_CONFIDENCE


def covers_wildcard(query: PermissionQuery) -> bool:
    """True when at least one matching allow has ``Resource: "*"``."""
    return any(resource_covers(r.statement, "*") for r in query.allows)


def covered_values(query: PermissionQuery, values: list[str]) -> list[str]:
    """Subset of ``values`` matched by the query's allow resource scopes."""
    return [
        v for v in values if any(resource_covers(r.statement, v) for r in query.allows)
    ]


def evidence_for(query: PermissionQuery) -> list[Evidence]:
    return [evidence_from_ref(r) for r in query.allows]


def scope_note(query: PermissionQuery, label: str = "Resource scope") -> str:
    if covers_wildcard(query):
        return f"{label}: * (any resource)"
    patterns = sorted({p for r in query.allows for p in r.statement.resources})
    return f"{label}: {', '.join(patterns) or 'unspecified'}"


def assumable_role_names(ctx: AnalysisContext, kind: str, name: str) -> set[str]:
    """Roles this principal could actually assume right now.

    Requires both the sts:AssumeRole permission covering the role ARN and a
    trust policy that admits the principal.
    """
    principal_arn = ctx.arn(kind, name)
    assume_query = ctx.eff(kind, name).query("sts:AssumeRole")
    if not assume_query.allowed:
        return set()
    assumable: set[str] = set()
    for role_name, role in ctx.account.roles.items():
        if not covered_values(assume_query, [role.arn]):
            continue
        if trust_allows(role, principal_arn).allowed:
            assumable.add(role_name)
    return assumable
