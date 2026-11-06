"""True-positive / false-positive tests for detection rules.

The contract enforced here is the heart of the repository:

* every registered rule has a ``tests/fixtures/vulnerable/<RULE_ID>.json``
  fixture that MUST trigger that rule;
* every registered rule has a ``tests/fixtures/safe/<RULE_ID>.json`` fixture
  that must produce ZERO findings of any rule (no false positives);
* fixtures and registry cannot drift apart.
"""

from __future__ import annotations

import pytest
from conftest import FIXTURES, load_fixture

from iam_pathfinder.analyzer import analyze_account
from iam_pathfinder.parser import parse_export
from iam_pathfinder.rules import Severity, all_rules, get_rule

RULE_IDS = [rule.id for rule in all_rules()]


def _findings(category: str, rule_id: str):
    parsed = parse_export(load_fixture(category, rule_id))
    _ctx, findings = analyze_account(parsed.account)
    return findings


def _finding_ids(findings) -> set[str]:
    return {f.rule_id for f in findings}


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_vulnerable_fixture_is_detected(rule_id: str) -> None:
    findings = _findings("vulnerable", rule_id)
    assert rule_id in _finding_ids(findings), (
        f"rule {rule_id} did not fire on its vulnerable fixture; "
        f"got findings: {sorted(_finding_ids(findings))}"
    )


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_safe_fixture_produces_no_findings(rule_id: str) -> None:
    findings = _findings("safe", rule_id)
    details = [(f.rule_id, f.principal_name) for f in findings]
    assert findings == [], f"false positives in safe fixture for {rule_id}: {details}"


def test_every_rule_has_both_fixtures() -> None:
    for rule_id in RULE_IDS:
        for category in ("vulnerable", "safe"):
            path = FIXTURES / category / f"{rule_id}.json"
            assert path.exists(), f"missing fixture {path}"


def test_no_orphan_fixtures() -> None:
    known = set(RULE_IDS)
    for category in ("vulnerable", "safe"):
        for path in (FIXTURES / category).glob("*.json"):
            assert path.stem in known, f"fixture {path} has no matching rule"


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_vulnerable_fixture_finding_has_required_fields(rule_id: str) -> None:
    findings = _findings("vulnerable", rule_id)
    finding = next(f for f in findings if f.rule_id == rule_id)
    rule = get_rule(rule_id)
    # Severity may be graded up or down per context; it must stay in range.
    assert Severity.LOW <= finding.severity <= Severity.CRITICAL
    assert rule.severity in tuple(Severity)
    assert finding.principal_arn.startswith("arn:aws:iam::")
    assert finding.permissions, "finding must list the permissions involved"
    assert finding.evidence, "finding must cite the source policy and statement"
    assert finding.explanation, "finding must explain itself in plain English"
    assert finding.remediation, "finding must include remediation"
    assert finding.confidence in {"high", "medium", "low"}
    assert finding.notes, "finding should carry scope/context notes"
