"""Plain-text table renderer (default format).

No third-party table library: the output is a fixed-width index followed by a
detail block per finding, which stays readable in terminals and in CI logs.
"""

from __future__ import annotations

import json
import textwrap

from ..rules.base import Finding
from .report import Report

_RULE_WIDTH = 30
_PRINCIPAL_WIDTH = 24


def _wrap(text: str, indent: str = "    ") -> list[str]:
    lines = textwrap.wrap(text, width=96 - len(indent), initial_indent=indent,
                          subsequent_indent=indent)
    return lines or [indent.rstrip()]


def _count(n: int, singular: str, plural: str | None = None) -> str:
    word = singular if n == 1 else (plural or singular + "s")
    return f"{n} {word}"


def _index_row(finding: Finding) -> str:
    sev = finding.severity.label.upper()
    principal = f"{finding.principal_type} {finding.principal_name}"
    return (
        f"{sev:<10} {finding.rule_id:<{_RULE_WIDTH}} "
        f"{principal[:_PRINCIPAL_WIDTH]:<{_PRINCIPAL_WIDTH}} {finding.title}"
    )


def _evidence_line(finding: Finding) -> str:
    parts = []
    for ev in finding.evidence[:3]:
        statement = json.dumps(ev.statement, sort_keys=True, separators=(",", ":"))
        parts.append(f"{ev.source_label}: {statement}")
    if len(finding.evidence) > 3:
        parts.append(f"... {len(finding.evidence) - 3} more statement(s)")
    return " | ".join(parts) if parts else "(no policy statement attached)"


def render(report: Report) -> str:
    out: list[str] = []
    bar = "=" * 96
    out.append(bar)
    out.append(f" iam-pathfinder {report.tool_version} - offline IAM analysis (no AWS API calls)")
    out.append(bar)
    if report.export_path:
        out.append(f" Export:   {report.export_path}")
    out.append(f" Account:  {report.account_id or 'unknown'}")
    scope = report.scope
    out.append(
        " Scope:    {users}, {groups}, {roles}, {policies}".format(
            users=_count(scope["users"], "user"),
            groups=_count(scope["groups"], "group"),
            roles=_count(scope["roles"], "role"),
            policies=_count(scope["managed_policies"], "managed policy"),
        )
    )
    counts = report.severity_counts
    out.append(
        " Findings: {total} ({critical} critical, {high} high, {medium} medium, "
        "{low} low)".format(total=len(report.findings), **counts)
    )
    out.append(f" Filter:   min-severity={report.min_severity.label}")
    out.append(
        " Escalation paths: "
        + (
            _count(len(report.paths), "path")
            + f" (longest {_count(max(p.length for p in report.paths), 'hop')})"
            if report.paths
            else "0 paths"
        )
    )
    out.append("")

    if not report.findings:
        out.append(" No findings at or above the severity filter.")
        out.append("")
        return "\n".join(out)

    # --- index ------------------------------------------------------------
    out.append(
        f"{'SEVERITY':<10} {'RULE':<{_RULE_WIDTH}} "
        f"{'PRINCIPAL':<{_PRINCIPAL_WIDTH}} TITLE"
    )
    out.append("-" * 96)
    for finding in report.findings:
        out.append(_index_row(finding))
    out.append("")

    # --- details ----------------------------------------------------------
    out.append("-" * 96)
    out.append(" DETAILS")
    out.append("-" * 96)
    for finding in report.findings:
        out.append("")
        out.append(
            f" [{finding.severity.label.upper()}] {finding.rule_id} - "
            f"{finding.principal_type} {finding.principal_name}"
        )
        out.append(f"   Title:       {finding.title}")
        out.append(
            f"   Confidence:  {finding.confidence}"
            + (" (conditional)" if finding.conditional else "")
        )
        out.append(f"   Permissions: {', '.join(finding.permissions) or '-'}")
        out.append("   What it means:")
        out.extend(_wrap(finding.explanation))
        out.append("   Evidence:")
        out.extend(_wrap(_evidence_line(finding)))
        out.append("   Remediation:")
        out.extend(_wrap(finding.remediation))
        for note in finding.notes:
            out.append(f"   Note: {note}")

    # --- escalation paths --------------------------------------------------
    if report.paths:
        out.append("")
        out.append("-" * 96)
        out.append(" ESCALATION PATHS (principal -> ... -> full admin)")
        out.append("-" * 96)
        for index, path in enumerate(report.paths, start=1):
            out.append(
                f"  {index}. [{_count(path.length, 'hop')}] {path.start}"
            )
            for step in path.steps:
                kind = "assume" if step.kind == "assume" else f"escalate ({step.rule_id})"
                out.append(f"       --{kind}--> {step.target}")
                out.append(f"            {step.detail}")

    if report.severity_counts.get("critical") or report.severity_counts.get("high"):
        out.append("")
        out.append(
            f" Next: review the {report.severity_counts.get('critical', 0)} critical and "
            f"{report.severity_counts.get('high', 0)} high finding(s) above; "
            "'iam-pathfinder explain RULE_ID' documents a rule in full."
        )
    out.append("")
    out.append(f" Highest severity present: {report.highest_severity.label}")
    return "\n".join(out)
