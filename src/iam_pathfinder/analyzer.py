"""Runs rules over an account and normalises the resulting findings.

Central policies implemented here (so no individual rule has to remember
them):

* principals that already hold full admin never receive escalation or
  combination findings - the FULL_ADMIN finding covers them instead;
* conditional findings and low-confidence findings get an explanatory note
  (LOW confidence is only ever caused by a partial explicit Deny in this
  codebase - see ``rules/escalation_single._confidence``);
* findings are sorted by severity, then rule id, then principal, so output
  is deterministic.
"""

from __future__ import annotations

from .context import AnalysisContext
from .model import Account
from .rules import ALL_RULES, Finding, Rule

_ESCALATION_CATEGORIES = ("escalation", "combination")

_CONDITIONAL_NOTE = (
    "Conditional: this statement only applies when its Condition is "
    "satisfied; conditions are not evaluated offline, so treat the "
    "finding as possible rather than certain."
)
_PARTIAL_DENY_NOTE = (
    "A narrower explicit Deny matches the same action, so the usable "
    "scope of this permission is uncertain (confidence lowered to low)."
)


def run_rules(ctx: AnalysisContext, rules: tuple[Rule, ...] | None = None) -> list[Finding]:
    """Evaluate all rules and return sorted findings."""
    selected = rules if rules is not None else ALL_RULES
    findings: list[Finding] = []
    for rule in selected:
        for finding in rule.check(ctx):
            if (
                rule.category in _ESCALATION_CATEGORIES
                and ctx.is_full_admin(finding.principal_type, finding.principal_name)
            ):
                # Already admin: escalation is moot; FULL_ADMIN reports it.
                continue
            if finding.conditional:
                finding.notes.append(_CONDITIONAL_NOTE)
            if finding.confidence == "low":
                finding.notes.append(_PARTIAL_DENY_NOTE)
            findings.append(finding)
    findings.sort(
        key=lambda f: (-int(f.severity), f.rule_id, f.principal_type, f.principal_name)
    )
    return findings


def analyze_account(account: Account) -> tuple[AnalysisContext, list[Finding]]:
    """Convenience wrapper: build a context and run every rule."""
    ctx = AnalysisContext(account=account)
    return ctx, run_rules(ctx)
