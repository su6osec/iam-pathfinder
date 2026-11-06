"""Rule framework: severities, findings and the base class every rule shares."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import TYPE_CHECKING, Any

from ..evaluator import StatementRef

if TYPE_CHECKING:  # pragma: no cover - import cycle guard
    from ..context import AnalysisContext


class Severity(IntEnum):
    """Finding severity.  Ordered so comparisons and filters are trivial."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @property
    def label(self) -> str:
        return self.name.lower()

    @classmethod
    def parse(cls, value: str) -> Severity:
        try:
            return cls[value.upper()]
        except KeyError as exc:
            choices = ", ".join(s.label for s in cls)
            raise ValueError(f"unknown severity {value!r} (choose from {choices})") from exc


# Confidence labels (plain strings so JSON output stays trivial).
HIGH_CONFIDENCE = "high"
MEDIUM_CONFIDENCE = "medium"
LOW_CONFIDENCE = "low"


@dataclass
class Evidence:
    """One policy statement that supports a finding."""

    policy_name: str
    policy_arn: str | None
    source_label: str
    statement: dict[str, Any]


def evidence_from_ref(ref: StatementRef) -> Evidence:
    return Evidence(
        policy_name=ref.policy_name,
        policy_arn=ref.policy_arn,
        source_label=ref.source_label,
        statement=ref.statement.raw,
    )


@dataclass
class Finding:
    """A single reported problem, complete enough to render on its own."""

    rule_id: str
    title: str
    severity: Severity
    confidence: str
    principal_arn: str
    principal_name: str
    principal_type: str  # "user" | "role" | "group"
    permissions: list[str]
    explanation: str
    remediation: str
    evidence: list[Evidence]
    conditional: bool = False
    notes: list[str] = field(default_factory=list)
    extras: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """JSON-serialisable representation used by the json/SARIF renderers."""
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.label,
            "confidence": self.confidence,
            "principal": {
                "arn": self.principal_arn,
                "name": self.principal_name,
                "type": self.principal_type,
            },
            "permissions": list(self.permissions),
            "explanation": self.explanation,
            "remediation": self.remediation,
            "conditional": self.conditional,
            "notes": list(self.notes),
            "evidence": [
                {
                    "policy_name": e.policy_name,
                    "policy_arn": e.policy_arn,
                    "source": e.source_label,
                    "statement": e.statement,
                }
                for e in self.evidence
            ],
            "extras": dict(self.extras),
        }


class Rule:
    """Base class for detection rules.

    Subclasses set the class attributes and implement :meth:`check`.
    ``category`` drives central behaviour: principals that already have
    full admin never get escalation/combination findings (the FULL_ADMIN
    finding covers them instead).
    """

    id: str = ""
    title: str = ""
    severity: Severity = Severity.MEDIUM
    category: str = "escalation"  # "escalation" | "combination" | "hygiene"
    explanation: str = ""
    remediation: str = ""
    references: list[str] = []
    required_permissions: list[str] = []
    principal_types: tuple[str, ...] = ("user", "role")

    def check(self, ctx: AnalysisContext) -> list[Finding]:  # pragma: no cover - abstract
        raise NotImplementedError

    def make_finding(
        self,
        ctx: AnalysisContext,
        principal_type: str,
        principal_name: str,
        *,
        permissions: list[str],
        explanation: str | None = None,
        evidence: list[Evidence] | None = None,
        severity: Severity | None = None,
        confidence: str = HIGH_CONFIDENCE,
        conditional: bool = False,
        notes: list[str] | None = None,
        extras: dict[str, Any] | None = None,
    ) -> Finding:
        """Build a finding with rule metadata and principal ARN filled in."""
        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=severity if severity is not None else self.severity,
            confidence=confidence,
            principal_arn=ctx.arn(principal_type, principal_name),
            principal_name=principal_name,
            principal_type=principal_type,
            permissions=permissions,
            explanation=explanation or self.explanation,
            remediation=self.remediation,
            evidence=evidence or [],
            conditional=conditional,
            notes=notes or [],
            extras=extras or {},
        )
