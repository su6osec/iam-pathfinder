"""Self-contained HTML renderer.

The document embeds all CSS and data - no scripts, no fonts, no images, no
external URLs are loaded, so the file is safe to share and works offline.
Every value coming from the export is HTML-escaped.
"""

from __future__ import annotations

import html
import json

from .report import Report

_CSS = """
:root { color-scheme: light dark; }
* { box-sizing: border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
       margin: 0; padding: 2rem; line-height: 1.5; background: #f8fafc; color: #0f172a; }
h1 { font-size: 1.5rem; margin: 0 0 .25rem; }
h2 { font-size: 1.15rem; margin-top: 2rem; border-bottom: 2px solid #e2e8f0;
     padding-bottom: .35rem; }
.sub { color: #64748b; font-size: .9rem; }
.banner { background: #fef3c7; border: 1px solid #f59e0b; border-radius: 8px;
          padding: .75rem 1rem; margin: 1rem 0; font-size: .9rem; }
.cards { display: flex; flex-wrap: wrap; gap: .75rem; margin: 1rem 0; }
.card { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;
        padding: .75rem 1rem; min-width: 8rem; }
.card .n { font-size: 1.4rem; font-weight: 700; }
.card .l { font-size: .75rem; text-transform: uppercase; letter-spacing: .05em;
           color: #64748b; }
table { border-collapse: collapse; width: 100%; background: #fff;
        border: 1px solid #e2e8f0; border-radius: 8px; overflow: hidden; font-size: .9rem; }
th, td { text-align: left; padding: .5rem .65rem; border-bottom: 1px solid #e2e8f0;
         vertical-align: top; }
th { background: #f1f5f9; font-size: .75rem; text-transform: uppercase;
     letter-spacing: .04em; color: #475569; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: .85em;
       background: #f1f5f9; padding: .1rem .3rem; border-radius: 4px; }
.sev { display: inline-block; padding: .1rem .45rem; border-radius: 999px;
       font-size: .72rem; font-weight: 700; text-transform: uppercase; }
.sev-critical { background: #7f1d1d; color: #fff; }
.sev-high { background: #b91c1c; color: #fff; }
.sev-medium { background: #b45309; color: #fff; }
.sev-low { background: #334155; color: #fff; }
details { background: #fff; border: 1px solid #e2e8f0; border-radius: 8px;
          padding: .6rem .9rem; margin: .6rem 0; }
summary { cursor: pointer; font-weight: 600; }
dl { display: grid; grid-template-columns: 10rem 1fr; gap: .25rem .75rem; margin: .75rem 0 0; }
dt { color: #64748b; font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; }
dd { margin: 0; font-size: .9rem; }
pre { background: #0f172a; color: #e2e8f0; padding: .6rem .8rem; border-radius: 6px;
      overflow-x: auto; font-size: .8rem; }
ol.paths li { margin: .5rem 0; }
footer { margin-top: 2.5rem; color: #64748b; font-size: .8rem; }
@media (prefers-color-scheme: dark) {
  body { background: #0f172a; color: #e2e8f0; }
  .card, table, details { background: #1e293b; border-color: #334155; }
  th { background: #334155; color: #cbd5e1; }
  th, td { border-color: #334155; }
  code { background: #334155; }
}
"""


def _esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _severity_badge(severity_label: str) -> str:
    return f'<span class="sev sev-{_esc(severity_label)}">{_esc(severity_label)}</span>'


def render(report: Report) -> str:
    scope = report.scope
    counts = report.severity_counts

    cards = "".join(
        f'<div class="card"><div class="n">{counts[label]}</div>'
        f'<div class="l">{label}</div></div>'
        for label in ("critical", "high", "medium", "low")
    )
    cards += (
        f'<div class="card"><div class="n">{len(report.paths)}</div>'
        '<div class="l">escalation paths</div></div>'
        f'<div class="card"><div class="n">{scope["users"] + scope["roles"]}</div>'
        '<div class="l">principals</div></div>'
    )

    rows = []
    for finding in report.findings:
        rows.append(
            "<tr>"
            f"<td>{_severity_badge(finding.severity.label)}</td>"
            f"<td><code>{_esc(finding.rule_id)}</code></td>"
            f"<td>{_esc(finding.principal_type)} "
            f"<strong>{_esc(finding.principal_name)}</strong></td>"
            f"<td>{_esc(finding.title)}</td>"
            f"<td>{_esc(finding.confidence)}</td>"
            "</tr>"
        )
    findings_table = (
        "<table><thead><tr><th>Severity</th><th>Rule</th><th>Principal</th>"
        "<th>Title</th><th>Confidence</th></tr></thead><tbody>"
        + ("".join(rows) or '<tr><td colspan="5">No findings.</td></tr>')
        + "</tbody></table>"
    )

    details = []
    for finding in report.findings:
        evidence = "".join(
            f"<li>{_esc(ev.source_label)}<pre>"
            f"{_esc(json.dumps(ev.statement, indent=2, sort_keys=True))}</pre></li>"
            for ev in finding.evidence
        ) or "<li>(no policy statement attached)</li>"
        notes = "".join(f"<li>{_esc(note)}</li>" for note in finding.notes)
        details.append(
            "<details>"
            f"<summary>{_severity_badge(finding.severity.label)} "
            f"<code>{_esc(finding.rule_id)}</code> - {_esc(finding.principal_type)} "
            f"{_esc(finding.principal_name)}</summary>"
            "<dl>"
            f"<dt>Title</dt><dd>{_esc(finding.title)}</dd>"
            f"<dt>Confidence</dt><dd>{_esc(finding.confidence)}"
            f"{' (conditional)' if finding.conditional else ''}</dd>"
            f"<dt>Permissions</dt><dd>{_esc(', '.join(finding.permissions) or '-')}</dd>"
            "<dt>What it means</dt><dd>"
            f"{_esc(finding.explanation)}</dd>"
            f"<dt>Evidence</dt><dd><ul>{evidence}</ul></dd>"
            f"<dt>Remediation</dt><dd>{_esc(finding.remediation)}</dd>"
            + (f"<dt>Notes</dt><dd><ul>{notes}</ul></dd>" if notes else "")
            + "</dl></details>"
        )

    if report.paths:
        path_items = "".join(
            f"<li><strong>{_esc(path.start)}</strong> "
            f"({path.length} hop{'s' if path.length != 1 else ''}) - "
            + " -> ".join(_esc(step.target) for step in path.steps)
            + "</li>"
            for path in report.paths
        )
        path_block = f'<ol class="paths">{path_items}</ol>'
    else:
        path_block = "<p>No path from a principal to full administrative control.</p>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>iam-pathfinder report - account {_esc(report.account_id or 'unknown')}</title>
<style>{_CSS}</style>
</head>
<body>
<h1>iam-pathfinder {_esc(report.tool_version)} - IAM analysis</h1>
<p class="sub">Account <code>{_esc(report.account_id or 'unknown')}</code>
&middot; export <code>{_esc(report.export_path or 'stdin')}</code>
&middot; generated {_esc(report.generated_at)}</p>
<div class="banner"><strong>Sensitive data.</strong> This report describes real
IAM permissions. Store and share it like the account export itself. Analysis ran
fully offline against the local export - no AWS API calls were made.</div>
<div class="cards">{cards}</div>
<h2>Scope</h2>
<p class="sub">{scope['users']} users, {scope['groups']} groups,
{scope['roles']} roles, {scope['managed_policies']} managed policies
&middot; minimum severity shown: {_esc(report.min_severity.label)}</p>
<h2>Findings ({len(report.findings)})</h2>
{findings_table}
<h2>Finding details</h2>
{''.join(details) or '<p>No findings.</p>'}
<h2>Escalation paths ({len(report.paths)})</h2>
{path_block}
<footer>Generated by iam-pathfinder {_esc(report.tool_version)}. This file is
self-contained: no scripts, styles, fonts or images are loaded from anywhere.</footer>
</body>
</html>
"""
