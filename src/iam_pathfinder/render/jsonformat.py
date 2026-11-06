"""JSON renderer - machine-readable output for pipelines."""

from __future__ import annotations

import json

from .report import Report


def payload(report: Report) -> dict:
    """The full report as a plain dict (also used by tests and the CLI)."""
    data = dict(report.meta_dict())
    data["findings"] = [f.to_dict() for f in report.findings]
    data["escalation_paths"] = [report.path_dict(p) for p in report.paths]
    return data


def render(report: Report) -> str:
    return json.dumps(payload(report), indent=2, sort_keys=False, default=str) + "\n"
