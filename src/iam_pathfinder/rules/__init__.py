"""Rule registry.

``ALL_RULES`` is the single source of truth: the CLI's ``rules``/``explain``
commands and the analyzer all read from it.  Adding a rule means adding a
class here - there is no other registration path.
"""

from __future__ import annotations

from .base import Finding, Rule, Severity
from .combination import COMBINATION_RULES
from .escalation_single import SINGLE_PERMISSION_RULES
from .hygiene import HYGIENE_RULES

ALL_RULES: tuple[Rule, ...] = (
    SINGLE_PERMISSION_RULES + COMBINATION_RULES + HYGIENE_RULES
)

_RULES_BY_ID: dict[str, Rule] = {rule.id: rule for rule in ALL_RULES}


def get_rule(rule_id: str) -> Rule:
    """Look up a rule by its stable id (case-insensitive)."""
    rule = _RULES_BY_ID.get(rule_id.upper())
    if rule is None:
        known = ", ".join(sorted(_RULES_BY_ID))
        raise KeyError(f"unknown rule {rule_id!r}; known rules: {known}")
    return rule


def all_rules() -> tuple[Rule, ...]:
    return ALL_RULES


__all__ = ["ALL_RULES", "Finding", "Rule", "Severity", "all_rules", "get_rule"]
