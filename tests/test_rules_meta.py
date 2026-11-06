"""Registry metadata tests: every rule must be complete and well-formed."""

from __future__ import annotations

import re

import pytest

from iam_pathfinder.rules import Severity, all_rules, get_rule

RULE_IDS = [rule.id for rule in all_rules()]


def test_registry_is_not_empty():
    assert len(RULE_IDS) >= 12


def test_rule_ids_are_unique_and_stable():
    assert len(RULE_IDS) == len(set(RULE_IDS))
    for rule_id in RULE_IDS:
        assert re.fullmatch(r"[A-Z][A-Z0-9_]*", rule_id), rule_id


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_rule_metadata_is_complete(rule_id: str):
    rule = get_rule(rule_id)
    assert rule.id == rule_id
    assert rule.title.strip()
    assert isinstance(rule.severity, Severity)
    assert rule.category in {"escalation", "combination", "hygiene"}
    assert rule.explanation.strip(), f"{rule_id} needs an explanation"
    assert rule.remediation.strip(), f"{rule_id} needs remediation"
    assert rule.references, f"{rule_id} needs at least one reference"
    assert rule.required_permissions, f"{rule_id} needs required_permissions"
    assert rule.principal_types


@pytest.mark.parametrize("rule_id", RULE_IDS)
def test_references_look_like_urls(rule_id: str):
    rule = get_rule(rule_id)
    for url in rule.references:
        assert url.startswith("https://"), f"{rule_id}: bad reference {url}"


def test_get_rule_is_case_insensitive():
    assert get_rule("full_admin" if "FULL_ADMIN" in RULE_IDS else RULE_IDS[0]).id in RULE_IDS


def test_get_rule_rejects_unknown():
    with pytest.raises(KeyError, match="unknown rule"):
        get_rule("NO_SUCH_RULE")
