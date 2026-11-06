"""``iam-pathfinder`` command line interface.

Commands:

* ``analyze`` - run the rule catalogue over an export and render findings;
* ``explain`` - document one rule (explanation, remediation, references);
* ``rules``   - list the whole rule catalogue.

Exit codes: ``0`` success, ``1`` a ``--fail-on`` threshold was reached,
``2`` a usage, input or parse error.
"""

from __future__ import annotations

import sys
from pathlib import Path

import typer

from . import __version__
from .analyzer import analyze_account
from .graph import DEFAULT_MAX_DEPTH, build_graph, find_paths
from .parser import ParseError, load_export
from .render import FORMATS, Report
from .render import render as render_format
from .rules import ALL_RULES, Severity, get_rule

EXIT_OK = 0
EXIT_FAIL_ON = 1
EXIT_ERROR = 2

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help=(
        "Offline AWS IAM privilege-escalation and risky-permission analyzer. "
        "Reads a local `aws iam get-account-authorization-details` export; "
        "never calls AWS."
    ),
)


def _version_callback(value: bool) -> None:
    if value:
        typer.echo(f"iam-pathfinder {__version__}")
        raise typer.Exit(code=EXIT_OK)


@app.callback()
def root(
    version: bool = typer.Option(
        False,
        "--version",
        callback=_version_callback,
        is_eager=True,
        help="Show the version and exit.",
    ),
) -> None:
    """Offline IAM analysis of a local ``get-account-authorization-details`` export."""


def _fail(message: str, code: int = EXIT_ERROR) -> None:
    typer.echo(f"error: {message}", err=True)
    raise typer.Exit(code=code)


def _parse_severity(value: str, option: str) -> Severity:
    try:
        return Severity.parse(value)
    except ValueError as exc:
        _fail(f"{option}: {exc}")


def _parse_format(value: str) -> str:
    fmt = value.lower()
    if fmt not in FORMATS:
        _fail(f"--format: unknown format {value!r} (choose from {', '.join(FORMATS)})")
    return fmt


def _write_or_echo(text: str, out: Path | None) -> None:
    if out is None:
        typer.echo(text, nl=not text.endswith("\n"))
        return
    try:
        out.write_text(text, encoding="utf-8")
    except OSError as exc:
        _fail(f"cannot write {out}: {exc}")
    typer.echo(f"wrote {out}", err=True)


@app.command()
def analyze(
    export: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        readable=True,
        help="Path to an `aws iam get-account-authorization-details` JSON export.",
    ),
    format: str = typer.Option(
        "table", "--format", "-f", help=f"Output format: {', '.join(FORMATS)}."
    ),
    min_severity: str = typer.Option(
        "low", "--min-severity", help="Hide findings below this severity (low..critical)."
    ),
    fail_on: str | None = typer.Option(
        None,
        "--fail-on",
        help="Exit 1 if any reported finding is at or above this severity.",
    ),
    out: Path | None = typer.Option(
        None, "--out", "-o", help="Write the report to a file instead of stdout."
    ),
    max_depth: int = typer.Option(
        DEFAULT_MAX_DEPTH,
        "--max-depth",
        min=1,
        help="Maximum number of hops in a reported escalation path.",
    ),
) -> None:
    """Analyze an IAM export and report risky permissions and escalation paths."""
    fmt = _parse_format(format)
    floor = _parse_severity(min_severity, "--min-severity")
    threshold = _parse_severity(fail_on, "--fail-on") if fail_on else None

    try:
        parsed = load_export(str(export))
    except ParseError as exc:
        _fail(f"{export}: {exc}")
    except OSError as exc:
        _fail(f"{export}: {exc}")

    ctx, findings = analyze_account(parsed.account)
    if parsed.unresolved_policy_arns:
        typer.echo(
            "warning: {} attached policy ARN(s) are not present in the export and "
            "were skipped: {}".format(
                len(parsed.unresolved_policy_arns),
                ", ".join(parsed.unresolved_policy_arns),
            ),
            err=True,
        )
    visible = [f for f in findings if f.severity >= floor]
    graph = build_graph(ctx, visible)
    paths = find_paths(graph, max_depth=max_depth)
    report = Report(
        ctx=ctx,
        findings=visible,
        paths=paths,
        graph=graph,
        export_path=str(export),
        min_severity=floor,
    )

    try:
        text = render_format(fmt, report)
    except ValueError as exc:  # pragma: no cover - guarded by _parse_format
        _fail(str(exc))
    _write_or_echo(text, out)

    if threshold is not None and any(f.severity >= threshold for f in visible):
        typer.echo(
            f"fail-on: {threshold.label} threshold reached "
            f"({sum(1 for f in visible if f.severity >= threshold)} finding(s))",
            err=True,
        )
        raise typer.Exit(code=EXIT_FAIL_ON)


@app.command()
def explain(
    rule_id: str = typer.Argument(..., help="Stable rule id, e.g. IAM_CREATE_POLICY_VERSION."),
) -> None:
    """Explain one rule: what it detects, why it matters, and how to fix it."""
    try:
        rule = get_rule(rule_id)
    except KeyError as exc:
        _fail(str(exc.args[0]))

    typer.echo(f"Rule:          {rule.id}")
    typer.echo(f"Title:         {rule.title}")
    typer.echo(f"Severity:      {rule.severity.label}")
    typer.echo(f"Category:      {rule.category}")
    typer.echo(f"Principals:    {', '.join(rule.principal_types)}")
    typer.echo(
        f"Permissions:   {', '.join(rule.required_permissions) or '(none specific)'}"
    )
    typer.echo("")
    typer.echo("What it detects:")
    for line in rule.explanation.splitlines():
        typer.echo(f"  {line}")
    typer.echo("")
    typer.echo("Remediation:")
    for line in rule.remediation.splitlines():
        typer.echo(f"  {line}")
    if rule.references:
        typer.echo("")
        typer.echo("References:")
        for url in rule.references:
            typer.echo(f"  {url}")


@app.command()
def rules(
    format: str = typer.Option("table", "--format", "-f", help="table or json."),
) -> None:
    """List every rule in the catalogue."""
    fmt = _parse_format(format)
    if fmt not in {"table", "json"}:
        _fail(f"--format: 'rules' supports table or json, not {fmt!r}")

    if fmt == "json":
        import json

        payload = [
            {
                "id": rule.id,
                "title": rule.title,
                "severity": rule.severity.label,
                "category": rule.category,
                "principals": list(rule.principal_types),
                "required_permissions": list(rule.required_permissions),
                "explanation": rule.explanation,
                "remediation": rule.remediation,
                "references": list(rule.references),
            }
            for rule in ALL_RULES
        ]
        typer.echo(json.dumps(payload, indent=2))
        return

    typer.echo(f"{len(ALL_RULES)} rules (iam-pathfinder {__version__})")
    typer.echo("")
    typer.echo(f"{'ID':<37} {'SEVERITY':<9} {'CATEGORY':<13} TITLE")
    typer.echo("-" * 100)
    for rule in ALL_RULES:
        typer.echo(
            f"{rule.id:<37} {rule.severity.label:<9} {rule.category:<13} {rule.title}"
        )
    typer.echo("")
    typer.echo("Use 'iam-pathfinder explain RULE_ID' for details.")


def main() -> None:
    """Console-script entry point (``iam-pathfinder``)."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
    sys.exit(EXIT_OK)
