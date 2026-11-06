"""The report object every renderer consumes.

A :class:`Report` is built once by the CLI and handed to a renderer; renderers
never re-derive facts, so all output formats describe exactly the same analysis.
All numbers in a report are computed from the parsed export - nothing is
estimated or invented.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from .. import __version__
from ..context import AnalysisContext
from ..graph import EscalationGraph, EscalationPath
from ..rules.base import Finding, Severity


@dataclass
class Report:
    """One analysis run, ready to be rendered."""

    ctx: AnalysisContext
    findings: list[Finding]
    paths: list[EscalationPath]
    graph: EscalationGraph
    export_path: str | None = None
    min_severity: Severity = Severity.LOW
    generated_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat(timespec="seconds")
    )

    # --- summary facts (all computed from the export) ----------------------

    @property
    def account_id(self) -> str | None:
        return self.ctx.account.account_id

    @property
    def tool_version(self) -> str:
        return __version__

    @property
    def scope(self) -> dict[str, int]:
        account = self.ctx.account
        return {
            "users": len(account.users),
            "groups": len(account.groups),
            "roles": len(account.roles),
            "managed_policies": len(account.managed_policies),
        }

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {s.label: 0 for s in reversed(Severity)}
        for finding in self.findings:
            counts[finding.severity.label] += 1
        return counts

    @property
    def highest_severity(self) -> Severity | None:
        return max((f.severity for f in self.findings), default=None)

    @property
    def rule_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for finding in self.findings:
            counts[finding.rule_id] = counts.get(finding.rule_id, 0) + 1
        return dict(sorted(counts.items()))

    def meta_dict(self) -> dict[str, object]:
        return {
            "tool": {
                "name": "iam-pathfinder",
                "version": self.tool_version,
                "offline": True,
                "note": "Analysis of a local export only; no AWS API calls are made.",
            },
            "export": self.export_path,
            "account_id": self.account_id,
            "generated_at": self.generated_at,
            "min_severity": self.min_severity.label,
            "summary": {
                "findings": len(self.findings),
                "by_severity": self.severity_counts,
                "by_rule": self.rule_counts,
                "principals": self.scope,
                "escalation_paths": len(self.paths),
                "longest_path": max((p.length for p in self.paths), default=0),
            },
        }

    def path_dict(self, path: EscalationPath) -> dict[str, object]:
        return {
            "start": path.start,
            "length": path.length,
            "end": path.end,
            "description": path.describe(),
            "steps": [
                {
                    "from": step.source,
                    "to": step.target,
                    "kind": step.kind,
                    "detail": step.detail,
                    "rule_id": step.rule_id,
                }
                for step in path.steps
            ],
        }
