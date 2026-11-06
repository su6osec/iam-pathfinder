"""End-to-end CLI tests (exit codes, formats, explain/rules commands)."""

from __future__ import annotations

import json
from pathlib import Path

from conftest import FIXTURES, export, policy_document, stmt, user
from typer.testing import CliRunner

from iam_pathfinder.cli import app

runner = CliRunner()

VULN_ADMIN = FIXTURES / "vulnerable" / "FULL_ADMIN.json"
SAFE_ADMIN = FIXTURES / "safe" / "FULL_ADMIN.json"


def _medium_only_export() -> dict:
    """A synthetic export whose only finding is medium severity."""
    return export(
        users=[
            user(
                "bob",
                inline=[
                    (
                        "Assume",
                        policy_document(
                            stmt("Allow", action="sts:AssumeRole", resource="*")
                        ),
                    )
                ],
            )
        ]
    )


def _run(*args: str):
    return runner.invoke(app, [str(a) for a in args])


class TestAnalyze:
    def test_table_is_default_and_succeeds(self):
        result = _run("analyze", VULN_ADMIN)
        assert result.exit_code == 0, result.output
        assert "iam-pathfinder" in result.output
        assert "FULL_ADMIN" in result.output
        assert "Remediation:" in result.output

    def test_every_format_succeeds(self):
        for fmt in ("table", "json", "markdown", "sarif", "mermaid", "html"):
            result = _run("analyze", VULN_ADMIN, "--format", fmt)
            assert result.exit_code == 0, f"{fmt}: {result.output}"
            assert result.output.strip(), fmt

    def test_json_output_is_valid_and_offline_flagged(self):
        result = _run("analyze", VULN_ADMIN, "--format", "json")
        data = json.loads(result.output)
        assert data["tool"]["offline"] is True
        assert data["summary"]["findings"] >= 1

    def test_mermaid_output_is_a_graph(self):
        result = _run("analyze", VULN_ADMIN, "--format", "mermaid")
        assert "graph TD" in result.output

    def test_out_writes_a_file(self, tmp_path: Path):
        target = tmp_path / "report.html"
        result = _run("analyze", VULN_ADMIN, "--format", "html", "--out", str(target))
        assert result.exit_code == 0, result.output
        assert target.exists()
        content = target.read_text(encoding="utf-8")
        assert content.startswith("<!DOCTYPE html>")
        assert "wrote" in result.output or target.name in result.output

    def test_min_severity_filters_findings(self):
        result = _run(
            "analyze", VULN_ADMIN, "--format", "json", "--min-severity", "critical"
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert all(f["severity"] == "critical" for f in data["findings"])

    def test_min_severity_above_everything_shows_none(self, tmp_path: Path):
        # Only a medium finding exists, so filtering to critical hides it.
        medium = _medium_only_export()
        target = tmp_path / "medium.json"
        target.write_text(json.dumps(medium), encoding="utf-8")
        result = _run("analyze", str(target), "--format", "table",
                      "--min-severity", "critical")
        assert result.exit_code == 0
        assert "No findings" in result.output

    def test_fail_on_triggers_exit_1(self):
        result = _run("analyze", VULN_ADMIN, "--fail-on", "critical")
        assert result.exit_code == 1, result.output

    def test_fail_on_below_threshold_exits_0(self, tmp_path: Path):
        target = tmp_path / "medium.json"
        target.write_text(json.dumps(_medium_only_export()), encoding="utf-8")
        result = _run("analyze", str(target), "--fail-on", "critical")
        assert result.exit_code == 0, result.output
        # ...but the same report does trip a lower threshold.
        result = _run("analyze", str(target), "--fail-on", "medium")
        assert result.exit_code == 1, result.output

    def test_fail_on_defaults_to_no_failure(self):
        result = _run("analyze", VULN_ADMIN)
        assert result.exit_code == 0

    def test_unknown_format_is_a_usage_error(self):
        result = _run("analyze", VULN_ADMIN, "--format", "csv")
        assert result.exit_code == 2
        assert "error:" in result.output

    def test_unknown_severity_is_a_usage_error(self):
        result = _run("analyze", VULN_ADMIN, "--min-severity", "extreme")
        assert result.exit_code == 2
        assert "error:" in result.output

    def test_missing_file_is_a_usage_error(self):
        result = _run("analyze", "does-not-exist.json")
        assert result.exit_code == 2

    def test_malformed_json_is_an_error(self, tmp_path: Path):
        bad = tmp_path / "bad.json"
        bad.write_text("{not json", encoding="utf-8")
        result = _run("analyze", str(bad))
        assert result.exit_code == 2
        assert "error:" in result.output

    def test_non_export_json_is_an_error(self, tmp_path: Path):
        wrong = tmp_path / "wrong.json"
        wrong.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
        result = _run("analyze", str(wrong))
        assert result.exit_code == 2
        assert "error:" in result.output

    def test_safe_fixture_reports_no_findings(self):
        result = _run("analyze", SAFE_ADMIN, "--format", "json")
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["summary"]["findings"] == 0

    def test_max_depth_is_validated(self):
        result = _run("analyze", VULN_ADMIN, "--max-depth", "0")
        assert result.exit_code == 2


class TestExplain:
    def test_explain_known_rule(self):
        result = _run("explain", "IAM_CREATE_ACCESS_KEY")
        assert result.exit_code == 0
        assert "Rule:          IAM_CREATE_ACCESS_KEY" in result.output
        assert "Remediation:" in result.output
        assert "References:" in result.output
        assert "https://" in result.output

    def test_explain_is_case_insensitive(self):
        assert _run("explain", "full_admin").exit_code == 0

    def test_explain_unknown_rule(self):
        result = _run("explain", "NOT_A_RULE")
        assert result.exit_code == 2
        assert "unknown rule" in result.output


class TestRules:
    def test_rules_lists_the_catalogue(self):
        result = _run("rules")
        assert result.exit_code == 0
        assert "23 rules" in result.output
        assert "FULL_ADMIN" in result.output
        assert "explain RULE_ID" in result.output

    def test_rules_json(self):
        result = _run("rules", "--format", "json")
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert len(data) == 23
        assert {"id", "severity", "explanation", "remediation"} <= set(data[0])

    def test_rules_rejects_unknown_format(self):
        result = _run("rules", "--format", "html")
        assert result.exit_code == 2


class TestMeta:
    def test_version_flag(self):
        result = _run("--version")
        assert result.exit_code == 0
        assert "iam-pathfinder" in result.output

    def test_no_args_shows_help(self):
        # typer/click print the help text for an empty invocation and exit
        # with their standard usage-error code.
        result = _run()
        assert result.exit_code == 2
        assert "Usage" in result.output
        assert "analyze" in result.output

    def test_analyze_requires_an_argument(self):
        result = _run("analyze")
        assert result.exit_code == 2


class TestOfflineGuarantee:
    def test_help_mentions_offline(self):
        result = _run("--help")
        assert result.exit_code == 0
        assert "never calls AWS" in result.output

    def test_analyzing_an_empty_export_works(self, tmp_path: Path):
        empty = tmp_path / "empty.json"
        empty.write_text(
            json.dumps(export(users=[user("nobody")])), encoding="utf-8"
        )
        result = _run("analyze", str(empty), "--format", "json")
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["summary"]["findings"] == 0
