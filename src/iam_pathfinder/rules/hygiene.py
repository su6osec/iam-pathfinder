"""Hygiene and exposure rules.

These rules do not describe an escalation *technique*; they report risky
permission shapes and dangerous trust configurations:

* FULL_ADMIN - literal ``Action: *`` on ``Resource: *``
* SERVICE_WILDCARD - service-wide patterns such as ``iam:*``
* BROAD_NOT_ACTION - ``NotAction`` grants that allow nearly everything
* STS_ASSUMEROLE_WILDCARD - ``sts:AssumeRole`` on ``*``
* TRUST_POLICY_PUBLIC / TRUST_POLICY_CROSS_ACCOUNT / TRUST_POLICY_ACCOUNT_ROOT

Hygiene rules report the allow *patterns as written*: unlike the escalation
rules, they do not subtract explicit denies (the pattern is worth reviewing
either way).  They run for users, roles and groups (a dangerous group
permission is inherited by every member).  Trust rules run for roles only.
"""

from __future__ import annotations

from ..context import AnalysisContext
from ..evaluator import StatementRef, is_universal_allow, resource_covers
from ..trust import (
    aws_principal_entries,
    has_external_id_condition,
    iam_account_of,
    is_public_principal,
    trust_allows,
)
from .base import (
    HIGH_CONFIDENCE,
    MEDIUM_CONFIDENCE,
    Evidence,
    Finding,
    Rule,
    Severity,
)
from .helpers import confidence_for, covers_wildcard, scope_note

AWS_EVAL_LOGIC = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html"
)
AWS_NOTACTION = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_notaction.html"
)
AWS_CONDITION_KEYS = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_condition-keys.html"
)


def _trust_evidence(role_name: str, statements) -> list[Evidence]:
    return [
        Evidence(
            policy_name=f"trust policy of role {role_name}",
            policy_arn=None,
            source_label=f'trust policy of role "{role_name}"',
            statement=stmt.raw,
        )
        for stmt in statements
    ]


class FullAdminRule(Rule):
    id = "FULL_ADMIN"
    title = "Principal has full administrator access (Action: * on Resource: *)"
    severity = Severity.CRITICAL
    category = "hygiene"
    principal_types = ("user", "role", "group")
    required_permissions = ["*"]
    references = [AWS_EVAL_LOGIC]
    explanation = (
        "This principal's policies grant every action on every resource with "
        "no conditions. For a user this means long-lived credentials (access "
        "keys, console password) can do anything in the account, including "
        "deleting log trails and granting itself new permissions. Admin access "
        "is sometimes intentional, but it should be an explicit, reviewed "
        "exception rather than a default."
    )
    remediation = (
        "Replace standing admin with permission sets / roles that require "
        "recent authentication (SSO, federation), MFA and short sessions. "
        "Scope admin policies with permissions boundaries and deny dangerous "
        "actions (iam:*, account-level changes) with explicit Deny statements."
    )

    def check(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        severity_by_type = {
            "user": Severity.CRITICAL,  # long-lived, directly usable credentials
            "group": Severity.HIGH,  # every member inherits standing admin
            "role": Severity.HIGH,  # commonly intentional, still standing admin
        }
        for kind, name in ctx.iter_principals(self.principal_types):
            if not ctx.is_full_admin(kind, name):
                continue
            eff = ctx.eff(kind, name)
            universal = [r for r in eff.allows if is_universal_allow(r.statement)]
            denies = [r for r in eff.denies if not r.statement.is_conditional]
            notes = [
                "Grants: every action on every resource (unconditional).",
                f"Explicit unconditional deny statements present: {len(denies)}."
                if denies
                else "No explicit deny statements narrow this access.",
            ]
            findings.append(
                self.make_finding(
                    ctx,
                    kind,
                    name,
                    permissions=["*"],
                    evidence=[
                        Evidence(
                            policy_name=r.policy_name,
                            policy_arn=r.policy_arn,
                            source_label=r.source_label,
                            statement=r.statement.raw,
                        )
                        for r in universal
                    ],
                    severity=severity_by_type[kind],
                    confidence=HIGH_CONFIDENCE,
                    notes=notes,
                    extras={"resource_scope": "*", "deny_count": len(denies)},
                )
            )
        return findings


def _service_wildcards(refs: list[StatementRef]) -> dict[str, list[StatementRef]]:
    """Map service name -> refs containing a ``<service>:*`` allow pattern."""
    found: dict[str, list[StatementRef]] = {}
    for ref in refs:
        for pattern in ref.statement.actions:
            if pattern == "*" or ":" not in pattern:
                continue  # Action: * is FULL_ADMIN's business
            service, _, rest = pattern.partition(":")
            if rest == "*" and "*" not in service and "?" not in service:
                found.setdefault(service.lower(), []).append(ref)
    return found


class ServiceWildcardRule(Rule):
    id = "SERVICE_WILDCARD"
    title = "Service-wide wildcard permission (e.g. iam:*)"
    severity = Severity.MEDIUM
    category = "hygiene"
    principal_types = ("user", "role", "group")
    required_permissions = ["<service>:*"]
    references = [AWS_EVAL_LOGIC]
    explanation = (
        "A pattern such as iam:* or s3:* grants every action of that service "
        "on the scoped resources. For the IAM service this is effectively "
        "administration of the identity plane (create users, keys, policies), "
        "which is a documented path to full account compromise; for other "
        "services it removes any least-privilege granularity within the "
        "service."
    )
    remediation = (
        "Replace service-wide wildcards with the specific actions the "
        "workload needs. If broad access is required, scope it tightly by "
        "Resource and review it as an exception."
    )

    def check(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        for kind, name in ctx.iter_principals(self.principal_types):
            eff = ctx.eff(kind, name)
            for service, refs in sorted(_service_wildcards(eff.allows).items()):
                conditional = all(r.statement.is_conditional for r in refs)
                severity = Severity.HIGH if service == "iam" else Severity.MEDIUM
                patterns = sorted(
                    {
                        p
                        for r in refs
                        for p in r.statement.actions
                        if p.lower().startswith(f"{service}:")
                    }
                )
                findings.append(
                    self.make_finding(
                        ctx,
                        kind,
                        name,
                        permissions=patterns,
                        evidence=[
                            Evidence(
                                policy_name=r.policy_name,
                                policy_arn=r.policy_arn,
                                source_label=r.source_label,
                                statement=r.statement.raw,
                            )
                            for r in refs
                        ],
                        severity=severity,
                        confidence=MEDIUM_CONFIDENCE if conditional else HIGH_CONFIDENCE,
                        conditional=conditional,
                        notes=[
                            f"Pattern(s): {', '.join(patterns)} grant every "
                            f"{service.upper()} action in scope."
                            + (
                                " The IAM service in particular can rewrite "
                                "policies and credentials (escalation path)."
                                if service == "iam"
                                else ""
                            )
                        ],
                        extras={"service": service, "patterns": patterns},
                    )
                )
        return findings


class BroadNotActionRule(Rule):
    id = "BROAD_NOT_ACTION"
    title = "Allow with NotAction grants broad access"
    severity = Severity.MEDIUM
    category = "hygiene"
    principal_types = ("user", "role", "group")
    required_permissions = ["<everything except listed>"]
    references = [AWS_NOTACTION, AWS_EVAL_LOGIC]
    explanation = (
        "A statement with NotAction inverts its action list: it allows every "
        "action EXCEPT the listed ones. On Resource: * this grants almost "
        "the whole account - the security impact depends on how much is "
        "excluded, which is why this rule reports the excluded list."
    )
    remediation = (
        "Rewrite NotAction statements as explicit allow lists of the actions "
        "actually needed. If a small exclusion list was used to mean "
        "'everything else', enumerate those actions instead."
    )

    def check(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        for kind, name in ctx.iter_principals(self.principal_types):
            eff = ctx.eff(kind, name)
            for ref in eff.allows:
                stmt = ref.statement
                if not stmt.not_actions or not resource_covers(stmt, "*"):
                    continue
                excluded = list(stmt.not_actions)
                severity = Severity.HIGH if len(excluded) <= 5 else Severity.MEDIUM
                shown = ", ".join(excluded[:10])
                if len(excluded) > 10:
                    shown += f", ... ({len(excluded)} total)"
                findings.append(
                    self.make_finding(
                        ctx,
                        kind,
                        name,
                        permissions=["<everything except listed>"],
                        evidence=[
                            Evidence(
                                policy_name=ref.policy_name,
                                policy_arn=ref.policy_arn,
                                source_label=ref.source_label,
                                statement=stmt.raw,
                            )
                        ],
                        severity=severity,
                        confidence=MEDIUM_CONFIDENCE,  # heuristic: impact depends
                        conditional=stmt.is_conditional,
                        notes=[
                            f"NotAction excludes only: {shown}."
                            if len(excluded) <= 5
                            else f"NotAction excludes {len(excluded)} action "
                            "patterns; practical impact depends on what is "
                            "left out.",
                            "Heuristic: the tool cannot judge how restrictive "
                            "the exclusions are in practice.",
                        ],
                        extras={"excluded": excluded},
                    )
                )
        return findings


class AssumeRoleWildcardRule(Rule):
    id = "STS_ASSUMEROLE_WILDCARD"
    title = "sts:AssumeRole with Resource: *"
    severity = Severity.MEDIUM
    category = "hygiene"
    principal_types = ("user", "role", "group")
    required_permissions = ["sts:AssumeRole"]
    references = [AWS_EVAL_LOGIC]
    explanation = (
        "sts:AssumeRole on Resource: * lets this principal assume ANY role "
        "that trusts it. Combined with roles that trust the account root or "
        "have weak trust policies, this usually means every such role is "
        "reachable; whether that is an escalation depends on which roles "
        "trust this principal and what they can do."
    )
    remediation = (
        "Scope sts:AssumeRole Resource to the specific roles this principal "
        "needs. Review roles whose trust includes this principal (or the "
        "account root) - they are the ones actually reachable."
    )

    def check(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        for kind, name in ctx.iter_principals(self.principal_types):
            eff = ctx.eff(kind, name)
            query = eff.query("sts:AssumeRole")
            if not query.allowed or not covers_wildcard(query):
                continue
            # Whose trust can this principal actually satisfy?
            if kind == "group":
                principal_arns = [
                    u.arn
                    for u in ctx.account.users.values()
                    if name in u.group_names
                ]
            else:
                principal_arns = [ctx.arn(kind, name)]
            trusting = [
                role_name
                for role_name, role in sorted(ctx.account.roles.items())
                if any(trust_allows(role, arn).allowed for arn in principal_arns)
            ]
            privileged = [r for r in trusting if ctx.is_privileged("role", r)]
            severity = Severity.HIGH if privileged else Severity.MEDIUM
            notes = [scope_note(query)]
            if privileged:
                notes.append(
                    "Trusted privileged role(s) reachable with this "
                    "permission: " + ", ".join(privileged)
                )
            elif trusting:
                notes.append(
                    "Roles that trust this principal (reachable): "
                    + ", ".join(trusting[:10])
                    + (" ..." if len(trusting) > 10 else "")
                )
            else:
                notes.append(
                    "No role in the export trusts this principal yet; the "
                    "permission becomes exploitable the moment one does."
                )
            findings.append(
                self.make_finding(
                    ctx,
                    kind,
                    name,
                    permissions=["sts:AssumeRole"],
                    evidence=[
                        Evidence(
                            policy_name=r.policy_name,
                            policy_arn=r.policy_arn,
                            source_label=r.source_label,
                            statement=r.statement.raw,
                        )
                        for r in query.allows
                    ],
                    severity=severity,
                    confidence=confidence_for(query),
                    conditional=query.conditional,
                    notes=notes,
                    extras={
                        "resource_scope": "*",
                        "trusting_roles": trusting,
                        "privileged_roles": privileged,
                    },
                )
            )
        return findings


class TrustPublicRule(Rule):
    id = "TRUST_POLICY_PUBLIC"
    title = "Role trust policy allows any principal (*)"
    severity = Severity.HIGH
    category = "hygiene"
    principal_types = ("role",)
    required_permissions = ["sts:AssumeRole"]
    references = [AWS_EVAL_LOGIC]
    explanation = (
        "The role's trust policy has Principal \"*\" with no condition, so "
        "any AWS principal that holds sts:AssumeRole permission on this role "
        "- including in-account principals with AssumeRole on '*' - is "
        "allowed to assume it. Public trusts are safe only when a "
        "restrictive Condition is present; this one has none."
    )
    remediation = (
        "Replace Principal \"*\" with the specific accounts, roles or "
        "services that need to assume the role, or add a restrictive "
        "condition (for example sts:ExternalId for cross-account access, or "
        "aws:PrincipalOrgID within an organization)."
    )

    def check(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        for _kind, name in ctx.iter_principals(("role",)):
            role = ctx.account.roles[name]
            if role.trust_policy is None:
                continue
            public_stmts = [
                s
                for s in role.trust_policy.statements
                if s.is_allow and is_public_principal(s) and not s.is_conditional
            ]
            if not public_stmts:
                continue
            findings.append(
                self.make_finding(
                    ctx,
                    "role",
                    name,
                    permissions=["sts:AssumeRole"],
                    evidence=_trust_evidence(name, public_stmts),
                    confidence=HIGH_CONFIDENCE,
                    notes=[
                        'Principal is "*" and the statement has no Condition.',
                        "Assuming still requires sts:AssumeRole permission "
                        "on this role; in-account principals with AssumeRole "
                        "on '*' can use this trust directly.",
                    ],
                    extras={"public_statements": len(public_stmts)},
                )
            )
        return findings


class TrustCrossAccountRule(Rule):
    id = "TRUST_POLICY_CROSS_ACCOUNT"
    title = "Role trusts an external AWS account without sts:ExternalId"
    severity = Severity.MEDIUM
    category = "hygiene"
    principal_types = ("role",)
    required_permissions = ["sts:AssumeRole"]
    references = [AWS_CONDITION_KEYS, AWS_EVAL_LOGIC]
    explanation = (
        "The role trusts principals from a different AWS account. Without an "
        "sts:ExternalId condition, any principal in that external account "
        "which holds sts:AssumeRole on this role can assume it - and if the "
        "external account is ever compromised, every role trusting it is "
        "too. ExternalId proves the role is being assumed by the intended "
        "integration rather than a lookalike."
    )
    remediation = (
        "Add an sts:ExternalId condition with a unique, secret external id "
        "for third-party integrations, or replace the external account "
        "principal with the specific external role/user ARNs that need "
        "access. If the trust is no longer needed, remove it."
    )

    def check(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        account_id = ctx.account.account_id
        if account_id is None:
            return findings  # cannot classify cross-account without it
        for _kind, name in ctx.iter_principals(("role",)):
            role = ctx.account.roles[name]
            if role.trust_policy is None:
                continue
            matched = []
            external: list[str] = []
            for stmt in role.trust_policy.statements:
                if not stmt.is_allow or has_external_id_condition(stmt):
                    continue
                entries = [
                    e
                    for e in aws_principal_entries(stmt)
                    if (acct := iam_account_of(e)) is not None and acct != account_id
                ]
                if entries:
                    matched.append(stmt)
                    external.extend(entries)
            if not matched:
                continue
            privileged = ctx.is_privileged("role", name)
            conditional = all(s.is_conditional for s in matched)
            findings.append(
                self.make_finding(
                    ctx,
                    "role",
                    name,
                    permissions=["sts:AssumeRole"],
                    evidence=_trust_evidence(name, matched),
                    severity=Severity.HIGH if privileged else Severity.MEDIUM,
                    confidence=MEDIUM_CONFIDENCE if conditional else HIGH_CONFIDENCE,
                    conditional=conditional,
                    notes=[
                        "External principal(s): " + ", ".join(sorted(set(external))),
                        (
                            "This role holds admin/escalation permissions: "
                            "assuming it yields those permissions."
                            if privileged
                            else "Impact equals this role's own permissions."
                        ),
                        "No sts:ExternalId condition on the trusting "
                        "statement(s).",
                    ],
                    extras={"external_principals": sorted(set(external))},
                )
            )
        return findings


class TrustAccountRootRule(Rule):
    id = "TRUST_POLICY_ACCOUNT_ROOT"
    title = "Role trusts the account root (informational)"
    severity = Severity.LOW
    category = "hygiene"
    principal_types = ("role",)
    required_permissions = ["sts:AssumeRole"]
    references = [AWS_EVAL_LOGIC]
    explanation = (
        "The role's trust policy includes this account's root principal "
        "(arn:aws:iam::ACCOUNT:root). That means any principal inside this "
        "account that holds sts:AssumeRole permission on this role can "
        "assume it - the common 'account delegation' pattern. It is "
        "informational here because it is usually intentional, but it makes "
        "any wildcard sts:AssumeRole permission immediately meaningful."
    )
    remediation = (
        "If the delegation is intentional, keep it and make sure no "
        "principal holds sts:AssumeRole on '*' unnecessarily. Otherwise "
        "replace the root principal with the specific roles/users that need "
        "access."
    )

    def check(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        account_id = ctx.account.account_id
        if account_id is None:
            return findings
        root_principal = f"arn:aws:iam::{account_id}:root"
        for _kind, name in ctx.iter_principals(("role",)):
            role = ctx.account.roles[name]
            if role.trust_policy is None:
                continue
            # A bare account id in Principal is equivalent to the account root
            # ARN (AWS treats the two the same way).
            root_entries = {root_principal, account_id}
            matched = [
                s
                for s in role.trust_policy.statements
                if s.is_allow
                and root_entries.intersection(aws_principal_entries(s))
            ]
            if not matched:
                continue
            conditional = all(s.is_conditional for s in matched)
            findings.append(
                self.make_finding(
                    ctx,
                    "role",
                    name,
                    permissions=["sts:AssumeRole"],
                    evidence=_trust_evidence(name, matched),
                    severity=Severity.LOW,
                    confidence=MEDIUM_CONFIDENCE if conditional else HIGH_CONFIDENCE,
                    conditional=conditional,
                    notes=[
                        f"Trust includes {root_principal}.",
                        "Common delegation pattern; review only if wildcard "
                        "sts:AssumeRole permissions exist in the account.",
                    ],
                    extras={"root_principal": root_principal},
                )
            )
        return findings


HYGIENE_RULES: tuple[Rule, ...] = (
    FullAdminRule(),
    ServiceWildcardRule(),
    BroadNotActionRule(),
    AssumeRoleWildcardRule(),
    TrustPublicRule(),
    TrustCrossAccountRule(),
    TrustAccountRootRule(),
)
