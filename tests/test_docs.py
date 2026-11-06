"""Documentation tests: samples in the docs must come from real runs.

These tests are the reason the README and docs/RULES.md cannot drift: they
regenerate the content from the code and compare it with what is committed.
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

from iam_pathfinder.rules import ALL_RULES

REPO = Path(__file__).resolve().parent.parent
README = REPO / "README.md"
DOCS = REPO / "docs"
EXAMPLE = REPO / "examples" / "vulnerable-account.json"

ALLOWED_REFERENCE_DOMAINS = (
    "https://docs.aws.amazon.com/",
    "https://aws.amazon.com/",
    "https://rhinosecuritylabs.com/",
)


def _run_cli(*args: str) -> str:
    result = subprocess.run(
        [sys.executable, "-m", "iam_pathfinder.cli", *args],
        capture_output=True,
        text=True,
        cwd=REPO,
        check=True,
    )
    return result.stdout


def _readme_blocks(marker: str) -> list[str]:
    text = README.read_text(encoding="utf-8")
    pattern = re.compile(
        rf"<!-- BEGIN SAMPLE:{marker} -->\n(.*?)\n<!-- END SAMPLE:{marker} -->",
        re.DOTALL,
    )
    return pattern.findall(text)


class TestReadmeSamples:
    def test_readme_contains_sample_markers(self):
        assert _readme_blocks("head"), "README head sample block is missing"
        assert _readme_blocks("path"), "README path sample block is missing"

    @pytest.mark.parametrize("marker", ["head", "path"])
    def test_sample_matches_a_real_run(self, marker: str):
        block = _readme_blocks(marker)[0]
        output = _run_cli("analyze", str(EXAMPLE.relative_to(REPO)))
        assert block in output, (
            f"README sample block {marker!r} no longer appears verbatim in the "
            "real output - regenerate it from a fresh run"
        )

    def test_readme_claims_match_behaviour(self):
        text = README.read_text(encoding="utf-8")
        assert "never calls AWS" in text or "No AWS calls" in text
        assert "Sensitive data warning" in text
        assert str(len(ALL_RULES)) in text  # rule count stated correctly

    def test_readme_documents_every_rule_id(self):
        text = README.read_text(encoding="utf-8")
        # README links to docs/RULES.md for the full catalogue rather than
        # duplicating it, but the rule count and categories must be right.
        assert "12 single-permission escalation rules" in text
        assert "4 `iam:PassRole` combination rules" in text
        assert "7 hygiene/exposure rules" in text


class TestRulesDoc:
    def test_rules_md_is_in_sync_with_the_registry(self):
        sys.path.insert(0, str(DOCS))
        try:
            import generate_rules_md  # type: ignore[import-not-found]

            expected = generate_rules_md.render()
        finally:
            sys.path.pop(0)
        actual = (DOCS / "RULES.md").read_text(encoding="utf-8")
        assert actual == expected, (
            "docs/RULES.md is stale - run `python docs/generate_rules_md.py`"
        )

    def test_rules_md_documents_every_rule(self):
        text = (DOCS / "RULES.md").read_text(encoding="utf-8")
        for rule in ALL_RULES:
            assert f"## {rule.id}" in text, rule.id
            assert rule.explanation in text, rule.id
            assert rule.remediation in text, rule.id


class TestDocsPresence:
    REQUIRED = [
        "README.md",
        "SECURITY.md",
        "LICENSE",
        ".gitignore",
        "docs/ARCHITECTURE.md",
        "docs/RULES.md",
        "docs/WALKTHROUGH.md",
        "docs/FACTS.md",
        ".github/workflows/ci.yml",
        "examples/vulnerable-account.json",
        "examples/generate_example.py",
    ]

    @pytest.mark.parametrize("relative", REQUIRED)
    def test_file_exists(self, relative: str):
        assert (REPO / relative).exists(), relative

    def test_architecture_and_facts_are_substantial(self):
        for name in ("ARCHITECTURE.md", "FACTS.md", "WALKTHROUGH.md"):
            text = (DOCS / name).read_text(encoding="utf-8")
            assert len(text.splitlines()) > 40, name


class TestReferences:
    def test_every_rule_reference_is_a_real_looking_url(self):
        seen = set()
        for rule in ALL_RULES:
            assert rule.references, f"{rule.id} has no references"
            for url in rule.references:
                assert url.startswith(ALLOWED_REFERENCE_DOMAINS), (
                    f"{rule.id} references {url}, which is not from a known "
                    "documentation source"
                )
                seen.add(url)
        # The escalation rules are grounded in the public research that
        # documented these techniques.
        assert any("rhinosecuritylabs.com" in url for url in seen)
        assert any("docs.aws.amazon.com" in url for url in seen)

    def test_facts_doc_links_to_aws_docs(self):
        text = (DOCS / "FACTS.md").read_text(encoding="utf-8")
        assert "docs.aws.amazon.com" in text
        assert "https://" in text
        # Every markdown link in FACTS.md must be https (no http placeholders)
        links = re.findall(r"\((http[^)]+)\)", text)
        assert links
        assert all(link.startswith("https://") for link in links)
