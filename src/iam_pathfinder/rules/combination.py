"""Combination escalation rules: iam:PassRole paired with a service action.

Passing a role is only dangerous together with the ability to *use* the role
somewhere: run an EC2 instance with its instance profile, create a Lambda
function that executes under it, or create a CloudFormation stack that
assumes it.  Each pairing is its own rule; a fourth rule reports a wildcard
iam:PassRole even when no known pairing is present.

Severity grading is context-sensitive (see docs/RULES.md):

* HIGH when the PassRole scope covers a role that itself holds admin or
  single-permission escalation permissions (becoming that role = escalating);
* MEDIUM otherwise (impact equals whatever roles can actually be passed).
"""

from __future__ import annotations

from ..context import AnalysisContext
from ..evaluator import PermissionQuery
from .base import Finding, Rule, Severity
from .helpers import (
    confidence_for,
    covered_values,
    covers_wildcard,
    evidence_for,
    scope_note,
)

RHINO_ESCALATION = (
    "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
)
AWS_EVAL_LOGIC = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html"
)


def _grade_pass_role(
    ctx: AnalysisContext, pass_query: PermissionQuery
) -> tuple[Severity, list[str], list[str]] | None:
    """Shared grading for PassRole scope.

    Returns ``(severity, covered_role_names, privileged_names)`` or ``None``
    when the scope covers no real role and is not a wildcard (nothing to
    pass today).
    """
    role_arns = [r.arn for r in ctx.account.roles.values()]
    wildcard = covers_wildcard(pass_query)
    covered = covered_values(pass_query, role_arns)
    names = [arn.rsplit("/", 1)[-1] for arn in covered]
    if not wildcard and not names:
        return None
    privileged = [n for n in names if ctx.is_privileged("role", n)]
    severity = Severity.HIGH if privileged else Severity.MEDIUM
    return severity, names, privileged


class _PassRolePairingRule(Rule):
    """Base for PassRole + <service action> pairings."""

    category = "combination"
    severity = Severity.HIGH
    service_actions: tuple[str, ...] = ()
    principal_types = ("user", "role")

    def _service_allowed(self, ctx: AnalysisContext, kind: str, name: str) -> bool:
        eff = ctx.eff(kind, name)
        return all(eff.query(action).allowed for action in self.service_actions)

    def check(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        for kind, name in ctx.iter_principals(self.principal_types):
            eff = ctx.eff(kind, name)
            pass_query = eff.query("iam:PassRole")
            if not pass_query.allowed:
                continue
            if not self._service_allowed(ctx, kind, name):
                continue
            graded = _grade_pass_role(ctx, pass_query)
            if graded is None:
                continue
            severity, covered_names, privileged = graded
            notes = [scope_note(pass_query)]
            if privileged:
                notes.append(
                    "Privileged role(s) in PassRole scope: " + ", ".join(privileged)
                )
            else:
                notes.append(
                    "No privileged roles in PassRole scope: impact equals the "
                    "permissions of whichever roles can be passed."
                )
            findings.append(
                self.make_finding(
                    ctx,
                    kind,
                    name,
                    permissions=["iam:PassRole", *self.service_actions],
                    evidence=evidence_for(pass_query),
                    severity=severity,
                    confidence=confidence_for(pass_query),
                    conditional=pass_query.conditional,
                    notes=notes,
                    extras={
                        "resource_scope": "*" if covers_wildcard(pass_query) else "scoped",
                        "covered_roles": covered_names,
                        "privileged_roles": privileged,
                        "pairing_actions": list(self.service_actions),
                    },
                )
            )
        return findings


class PassRoleEc2Rule(_PassRolePairingRule):
    id = "PASSROLE_EC2_RUNINSTANCES"
    title = "Pass a role to a new EC2 instance (instance profile)"
    required_permissions = ["iam:PassRole", "ec2:RunInstances"]
    service_actions = ("ec2:RunInstances",)
    references = [RHINO_ESCALATION]
    explanation = (
        "iam:PassRole plus ec2:RunInstances lets this principal launch an EC2 "
        "instance with an instance profile of its choosing. The instance "
        "receives the role's credentials via the instance metadata service, so "
        "whoever can log into or run code on that instance acts with the "
        "role's permissions."
    )
    remediation = (
        "Remove ec2:RunInstances or iam:PassRole from this principal. Scope "
        "iam:PassRole Resource to specific service roles that never hold "
        "admin/escalation permissions, and require instance-launch policies "
        "to pin allowed AMIs, instance types and IAM instance profiles."
    )


class PassRoleLambdaRule(_PassRolePairingRule):
    id = "PASSROLE_LAMBDA_CREATE_INVOKE"
    title = "Pass a role to a new Lambda function, then invoke it"
    required_permissions = [
        "iam:PassRole",
        "lambda:CreateFunction",
        "lambda:InvokeFunction",
    ]
    service_actions = ("lambda:CreateFunction", "lambda:InvokeFunction")
    references = [RHINO_ESCALATION]
    explanation = (
        "iam:PassRole with lambda:CreateFunction and lambda:InvokeFunction "
        "lets this principal deploy a Lambda function that runs under a role "
        "of its choosing and then trigger it. The function's code executes "
        "with the role's permissions, so a privileged role in scope means "
        "full compromise of whatever that role can do."
    )
    remediation = (
        "Remove lambda:CreateFunction/lambda:InvokeFunction or restrict "
        "iam:PassRole to non-privileged, task-specific roles. Review existing "
        "Lambda functions for unexpected roles and unexpected invokers."
    )


class PassRoleCloudFormationRule(_PassRolePairingRule):
    id = "PASSROLE_CLOUDFORMATION_CREATE_STACK"
    title = "Pass a role to a new CloudFormation stack"
    required_permissions = ["iam:PassRole", "cloudformation:CreateStack"]
    service_actions = ("cloudformation:CreateStack",)
    references = [RHINO_ESCALATION]
    explanation = (
        "iam:PassRole with cloudformation:CreateStack lets this principal "
        "create a stack whose resources are created using a service role of "
        "its choosing. A template can create administrative users, policies "
        "or other resources with that role's permissions."
    )
    remediation = (
        "Remove cloudformation:CreateStack or restrict iam:PassRole to "
        "non-privileged stack roles. Use CloudFormation service-managed "
        "permissions (service-managed lifecycle) where possible instead of "
        "customer-passed roles."
    )


class PassRoleWildcardRule(Rule):
    id = "PASSROLE_WILDCARD"
    title = "iam:PassRole with Resource: *"
    severity = Severity.MEDIUM
    category = "combination"
    required_permissions = ["iam:PassRole"]
    principal_types = ("user", "role")
    references = [RHINO_ESCALATION, AWS_EVAL_LOGIC]
    explanation = (
        "iam:PassRole on Resource: * lets this principal hand ANY role in the "
        "account to a service that runs code on its behalf (EC2, Lambda, "
        "CloudFormation, Glue, Data Pipeline and others). Even without a "
        "known pairing today, any future service permission - or a service "
        "this tool does not model - turns this into privilege escalation."
    )
    remediation = (
        "Scope iam:PassRole Resource to the specific role ARNs this principal "
        "legitimately needs to pass, and never to '*'. Pair the scoped roles "
        "with permissions-boundaried, task-specific policies."
    )

    def check(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        for kind, name in ctx.iter_principals(self.principal_types):
            eff = ctx.eff(kind, name)
            pass_query = eff.query("iam:PassRole")
            if not pass_query.allowed or not covers_wildcard(pass_query):
                continue
            # When a known pairing already applies, that pairing's rule
            # reports the specific technique; do not double-report.
            pairing_applies = (
                eff.query("ec2:RunInstances").allowed
                or (
                    eff.query("lambda:CreateFunction").allowed
                    and eff.query("lambda:InvokeFunction").allowed
                )
                or eff.query("cloudformation:CreateStack").allowed
            )
            if pairing_applies:
                continue
            findings.append(
                self.make_finding(
                    ctx,
                    kind,
                    name,
                    permissions=["iam:PassRole"],
                    evidence=evidence_for(pass_query),
                    confidence=confidence_for(pass_query),
                    conditional=pass_query.conditional,
                    notes=[
                        scope_note(pass_query),
                        "No known service pairing (EC2/Lambda/CloudFormation) "
                        "found in this principal's permissions; reported as a "
                        "risky permission rather than a confirmed path.",
                    ],
                    extras={"resource_scope": "*", "pairing_actions": []},
                )
            )
        return findings


COMBINATION_RULES: tuple[Rule, ...] = (
    PassRoleEc2Rule(),
    PassRoleLambdaRule(),
    PassRoleCloudFormationRule(),
    PassRoleWildcardRule(),
)
