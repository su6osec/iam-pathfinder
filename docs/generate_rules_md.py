#!/usr/bin/env python3
"""Regenerate ``docs/RULES.md`` from the rule registry.

    python docs/generate_rules_md.py

The file is committed, and ``tests/test_docs.py`` re-runs this generator and
fails if the committed file differs from the registry - documentation cannot
drift away from the code.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "src"))

from iam_pathfinder.rules import ALL_RULES  # noqa: E402
from iam_pathfinder.rules.base import Rule  # noqa: E402

OUT = Path(__file__).resolve().parent / "RULES.md"


def _summary_table() -> list[str]:
    lines = [
        "| Rule id | Severity | Category | Principals | Title |",
        "| --- | --- | --- | --- | --- |",
    ]
    for rule in ALL_RULES:
        lines.append(
            f"| [`{rule.id}`](#{rule.id.lower()}) | {rule.severity.label} "
            f"| {rule.category} | {', '.join(rule.principal_types)} | {rule.title} |"
        )
    return lines


def _section(rule: Rule) -> list[str]:
    lines = [
        f"## {rule.id}",
        "",
        f"* **Title:** {rule.title}",
        f"* **Severity:** {rule.severity.label}",
        f"* **Category:** {rule.category}",
        f"* **Principals:** {', '.join(rule.principal_types)}",
        "* **Required permissions:** "
        + (", ".join(f"`{p}`" for p in rule.required_permissions) or "-"),
        "",
        rule.explanation,
        "",
        "**Remediation.** " + rule.remediation,
        "",
    ]
    if rule.references:
        lines.append("**References.**")
        lines.append("")
        lines.extend(f"* <{url}>" for url in rule.references)
        lines.append("")
    return lines


def render() -> str:
    counts: dict[str, int] = {}
    for rule in ALL_RULES:
        counts[rule.category] = counts.get(rule.category, 0) + 1
    breakdown = ", ".join(f"{n} {cat}" for cat, n in sorted(counts.items()))

    parts = [
        "# Rule catalogue",
        "",
        "> Generated from `iam_pathfinder.rules.ALL_RULES` by",
        "> `python docs/generate_rules_md.py`. Do not edit by hand: the test",
        "> suite regenerates this file and fails if it drifts from the code.",
        "",
        f"**{len(ALL_RULES)} rules** ({breakdown}).",
        "",
        "## Summary",
        "",
        *_summary_table(),
        "",
        "Severity is the default severity for the rule; a finding can be graded",
        "higher or lower per principal (for example `FULL_ADMIN` is `critical` for",
        "a user but `high` for a role or group, and `NotAction`-derived findings",
        "are capped at medium confidence). Confidence is reported separately:",
        "`high` for unconditional statements, `medium` when a `Condition` applies",
        "or `NotAction` is involved, `low` when an explicit deny narrows the",
        "usable scope.",
        "",
    ]
    for rule in ALL_RULES:
        parts.extend(_section(rule))
    return "\n".join(parts).rstrip("\n") + "\n"


def main() -> None:
    OUT.write_text(render(), encoding="utf-8")
    print(f"wrote {OUT} ({len(ALL_RULES)} rules)")


if __name__ == "__main__":
    main()
