"""Tests for every output format.

All renderers consume the same :class:`Report`, so these tests also assert the
cross-format invariant: the same findings appear everywhere.
"""

from __future__ import annotations

import json
import re

from conftest import export, policy_document, role, stmt, user, user_arn

from iam_pathfinder.analyzer import analyze_account
from iam_pathfinder.graph import ESCALATING_RULES, build_graph, find_paths
from iam_pathfinder.parser import parse_export
from iam_pathfinder.render import FORMATS, Report, render
from iam_pathfinder.rules import ALL_RULES, Severity

SCARY_POLICY = "<script>alert('xss')</script>"


def _report(data: dict, min_severity: Severity = Severity.LOW) -> Report:
    parsed = parse_export(data)
    ctx, findings = analyze_account(parsed.account)
    visible = [f for f in findings if f.severity >= min_severity]
    graph = build_graph(ctx, visible)
    return Report(
        ctx=ctx,
        findings=visible,
        paths=find_paths(graph),
        graph=graph,
        export_path="export.json",
        min_severity=min_severity,
    )


def _rich_export() -> dict:
    """An export with an admin user, an assumable admin role and a scary policy name."""
    return export(
        users=[
            user(
                "alice",
                inline=[
                    (
                        "Admin",
                        policy_document(stmt("Allow", action="*", resource="*")),
                    ),
                    (
                        SCARY_POLICY,
                        policy_document(
                            stmt("Allow", action="sts:AssumeRole", resource="*")
                        ),
                    ),
                ],
            )
        ],
        roles=[
            role(
                "admin",
                trust=policy_document(
                    stmt("Allow", Principal={"AWS": user_arn("alice")}, Resource="*")
                ),
                inline=[
                    (
                        "Admin",
                        policy_document(stmt("Allow", action="*", resource="*")),
                    )
                ],
            )
        ],
    )


def _empty_report() -> Report:
    data = export(users=[user("bob")])
    parsed = parse_export(data)
    ctx, findings = analyze_account(parsed.account)
    graph = build_graph(ctx, findings)
    return Report(ctx=ctx, findings=findings, paths=find_paths(graph), graph=graph)


class TestDispatch:
    def test_all_formats_are_registered(self):
        assert FORMATS == ("table", "json", "markdown", "sarif", "mermaid", "html")
        report = _report(_rich_export())
        for fmt in FORMATS:
            text = render(fmt, report)
            assert isinstance(text, str) and text.strip(), fmt

    def test_unknown_format_raises(self):
        report = _report(_rich_export())
        try:
            render("csv", report)
        except ValueError as exc:
            assert "unknown format" in str(exc)
        else:  # pragma: no cover
            raise AssertionError("expected ValueError")


class TestTable:
    def test_contains_findings_and_remediation(self):
        text = render("table", _report(_rich_export()))
        assert "FULL_ADMIN" in text
        assert "user alice" in text
        assert "Remediation:" in text
        assert "ESCALATION PATHS" in text
        assert "no AWS API calls" in text
        assert "\x1b[" not in text  # no ANSI escapes

    def test_empty_report_says_so(self):
        text = render("table", _empty_report())
        assert "No findings" in text


class TestJson:
    def test_payload_shape(self):
        report = _report(_rich_export())
        data = json.loads(render("json", report))
        assert data["tool"]["name"] == "iam-pathfinder"
        assert data["tool"]["offline"] is True
        assert data["account_id"] == "123456789012"
        assert data["export"] == "export.json"
        assert data["summary"]["findings"] == len(report.findings)
        assert sum(data["summary"]["by_severity"].values()) == len(report.findings)
        assert len(data["findings"]) == len(report.findings)
        assert len(data["escalation_paths"]) == len(report.paths)
        first = data["findings"][0]
        for key in ("rule_id", "severity", "principal", "explanation", "remediation",
                    "evidence"):
            assert key in first

    def test_paths_are_serialised(self):
        data = json.loads(render("json", _report(_rich_export())))
        assert data["escalation_paths"], "expected at least one escalation path"
        path = data["escalation_paths"][0]
        assert path["length"] == len(path["steps"])
        assert path["end"] == "virtual:admin"
        assert path["description"]


class TestMarkdown:
    def test_markdown_structure(self):
        text = render("markdown", _report(_rich_export()))
        assert text.startswith("# IAM analysis")
        assert "## Findings" in text
        assert "Remediation." in text
        assert "no AWS API calls were made" in text
        assert "Escalation paths" in text


class TestSarif:
    def test_sarif_envelope(self):
        report = _report(_rich_export())
        data = json.loads(render("sarif", report))
        assert data["version"] == "2.1.0"
        assert data["$schema"].startswith("https://")
        run = data["runs"][0]
        rules = run["tool"]["driver"]["rules"]
        assert len(rules) == 23
        assert {r["id"] for r in rules} == {r.id for r in ALL_RULES}
        results = run["results"]
        assert len(results) == len(report.findings)
        assert all(r["ruleId"] in {x["id"] for x in rules} for r in results)
        assert all(r["level"] in {"error", "warning", "note", "none"} for r in results)
        assert all("partialFingerprints" in r for r in results)

    def test_severity_maps_to_sarif_levels(self):
        report = _report(_rich_export())
        data = json.loads(render("sarif", report))
        levels = {r["ruleId"]: r["level"] for r in data["runs"][0]["results"]}
        assert levels.get("FULL_ADMIN") == "error"

    def test_information_uri_is_the_real_repository(self):
        from iam_pathfinder import REPOSITORY_URL

        data = json.loads(render("sarif", _report(_rich_export())))
        uri = data["runs"][0]["tool"]["driver"]["informationUri"]
        assert uri == REPOSITORY_URL
        assert "github.com/su6osec/iam-pathfinder" in uri
        assert "example" not in uri


class TestMermaid:
    def test_mermaid_graph(self):
        text = render("mermaid", _report(_rich_export()))
        assert text.startswith("%%")
        assert "\ngraph TD\n" in text
        assert "escalate FULL_ADMIN" in text
        assert "classDef virtual" in text
        # node definitions use sanitised ids (no raw ARN punctuation)
        definitions = [
            line for line in text.splitlines() if '["' in line and not line.startswith("%%")
        ]
        assert definitions
        for line in definitions:
            node_id = line.strip().split("[")[0]
            assert re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", node_id), line
        assert '"alice (user)"' in text

    def test_empty_graph_renders(self):
        text = render("mermaid", _empty_report())
        assert "graph TD" in text
        assert "(none)" in text


class TestHtml:
    def test_self_contained(self):
        text = render("html", _report(_rich_export()))
        assert text.startswith("<!DOCTYPE html>")
        assert "<style>" in text
        # no external assets: no scripts, no remote stylesheets/fonts/images
        assert "<script" not in text.lower()
        assert "src=" not in text.lower()
        assert 'href="http' not in text.lower()
        assert "http://" not in text
        assert "https://" not in text

    def test_user_controlled_text_is_escaped(self):
        text = render("html", _report(_rich_export()))
        assert "<script>alert" not in text
        assert "&lt;script&gt;" in text

    def test_empty_report_renders(self):
        text = render("html", _empty_report())
        assert "No findings." in text


class TestCrossFormatConsistency:
    def test_every_format_reports_the_same_rule_ids(self):
        report = _report(_rich_export())
        expected = {f.rule_id for f in report.findings}
        assert expected
        for fmt in FORMATS:
            text = render(fmt, report)
            if fmt == "json":
                ids = {f["rule_id"] for f in json.loads(text)["findings"]}
                assert ids == expected, fmt
            elif fmt == "sarif":
                ids = {r["ruleId"] for r in json.loads(text)["runs"][0]["results"]}
                assert ids == expected, fmt
            elif fmt == "mermaid":
                # The diagram shows the escalation graph, so only rules that
                # become graph edges appear; every other format lists findings.
                escalates = {f.rule_id for f in report.findings} & set(ESCALATING_RULES)
                assert escalates
                for rule_id in escalates:
                    assert rule_id in text, f"mermaid is missing {rule_id}"
            else:
                for rule_id in expected:
                    assert rule_id in text, f"{fmt} is missing {rule_id}"

    def test_min_severity_filter_is_reflected_everywhere(self):
        report = _report(_rich_export(), min_severity=Severity.CRITICAL)
        assert {f.severity for f in report.findings} <= {Severity.CRITICAL}
        assert any(f.rule_id == "FULL_ADMIN" for f in report.findings)
        for fmt in FORMATS:
            text = render(fmt, report)
            if fmt == "sarif":
                results = json.loads(text)["runs"][0]["results"]
                assert results, "critical findings must survive the filter"
                assert all(r["ruleId"] != "STS_ASSUMEROLE_WILDCARD" for r in results)
            else:
                assert "STS_ASSUMEROLE_WILDCARD" not in text, fmt
