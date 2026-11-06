"""Single-permission privilege-escalation rules.

Each class implements one technique from the publicly documented IAM
privilege-escalation methods (Rhino Security Labs, "AWS IAM Privilege
Escalation - Methods and Mitigation").  Severity is graded with account
context: whether the resource scope is ``*``, whether the target benefits
the principal directly, and whether conditions apply.

Rules here run for users and roles.  Principals that already hold full admin
are filtered out centrally (see ``analyzer.run_rules``): the FULL_ADMIN
finding covers them instead.
"""

from __future__ import annotations

from ..context import AnalysisContext
from ..evaluator import PermissionQuery, resource_covers
from ..trust import trust_allows
from .base import (
    HIGH_CONFIDENCE,
    LOW_CONFIDENCE,
    MEDIUM_CONFIDENCE,
    Evidence,
    Finding,
    Rule,
    Severity,
    evidence_from_ref,
)

RHINO_ESCALATION = (
    "https://rhinosecuritylabs.com/aws/aws-privilege-escalation-methods-mitigation/"
)
AWS_EVAL_LOGIC = (
    "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html"
)
AWS_IAM_ACTIONS = "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_actions.html"


# --- shared helpers --------------------------------------------------------


def _confidence(query: PermissionQuery) -> str:
    if query.partial_denies:
        return LOW_CONFIDENCE
    if query.conditional:
        return MEDIUM_CONFIDENCE
    return HIGH_CONFIDENCE


def _covers_wildcard(query: PermissionQuery) -> bool:
    """True when at least one matching allow has ``Resource: "*"``."""
    return any(resource_covers(r.statement, "*") for r in query.allows)


def _covered_values(query: PermissionQuery, values: list[str]) -> list[str]:
    """Subset of ``values`` matched by the query's allow resource scopes."""
    return [
        v for v in values if any(resource_covers(r.statement, v) for r in query.allows)
    ]


def _evidence(query: PermissionQuery) -> list[Evidence]:
    return [evidence_from_ref(r) for r in query.allows]


def _scope_note(query: PermissionQuery, label: str = "Resource scope") -> str:
    if _covers_wildcard(query):
        return f"{label}: * (any resource)"
    patterns = sorted({p for r in query.allows for p in r.statement.resources})
    return f"{label}: {', '.join(patterns) or 'unspecified'}"


def _assumable_role_names(ctx: AnalysisContext, kind: str, name: str) -> set[str]:
    """Roles this principal could actually assume right now.

    Requires both the sts:AssumeRole permission covering the role ARN and a
    trust policy that admits the principal.
    """
    principal_arn = ctx.arn(kind, name)
    assume_query = ctx.eff(kind, name).query("sts:AssumeRole")
    if not assume_query.allowed:
        return set()
    assumable: set[str] = set()
    for role_name, role in ctx.account.roles.items():
        if not _covered_values(assume_query, [role.arn]):
            continue
        if trust_allows(role, principal_arn).allowed:
            assumable.add(role_name)
    return assumable


class CreatePolicyVersionRule(Rule):
    id = "IAM_CREATE_POLICY_VERSION"
    title = "Create a new version of an IAM policy the principal can modify"
    severity = Severity.HIGH
    category = "escalation"
    required_permissions = ["iam:CreatePolicyVersion"]
    references = [RHINO_ESCALATION, AWS_IAM_ACTIONS]
    explanation = (
        "iam:CreatePolicyVersion lets this principal create a new version of the "
        "listed IAM policies, and the --set-as-default flag makes it active "
        "without needing iam:SetDefaultPolicyVersion. The new version can grant "
        "any permissions, so whoever controls this principal can turn one of "
        "these policies into an administrator policy and inherit its permissions."
    )
    remediation = (
        "Remove iam:CreatePolicyVersion from the principal's policies. Where IAM "
        "access is genuinely needed, scope Resource to specific read-only policy "
        "ARNs, or delegate policy management to a dedicated administrative role "
        "with permissions boundaries."
    )

    def check(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        for kind, name in ctx.iter_principals(self.principal_types):
            query = ctx.eff(kind, name).query("iam:CreatePolicyVersion")
            if not query.allowed:
                continue
            own_policies = ctx.attached_local_policy_arns(kind, name)
            wildcard = _covers_wildcard(query)
            covers_own = bool(_covered_values(query, own_policies))
            if not wildcard and not covers_own:
                # Scoped to policies the principal does not own: modifying
                # someone else's policy cannot benefit this principal.
                continue
            scope = (
                "any policy in the account (Resource: *)"
                if wildcard
                else "the local managed policies attached to this principal"
            )
            findings.append(
                self.make_finding(
                    ctx,
                    kind,
                    name,
                    permissions=["iam:CreatePolicyVersion"],
                    evidence=_evidence(query),
                    confidence=_confidence(query),
                    conditional=query.conditional,
                    notes=[_scope_note(query), f"Reachable targets: {scope}"],
                    extras={"resource_scope": "*" if wildcard else "attached-policies"},
                )
            )
        return findings


class SetDefaultPolicyVersionRule(Rule):
    id = "IAM_SET_DEFAULT_POLICY_VERSION"
    title = "Activate a different version of an IAM policy"
    severity = Severity.MEDIUM
    category = "escalation"
    required_permissions = ["iam:SetDefaultPolicyVersion"]
    references = [RHINO_ESCALATION, AWS_IAM_ACTIONS]
    explanation = (
        "iam:SetDefaultPolicyVersion switches which stored version of a policy is "
        "active. If any non-default version is broader than the current one "
        "(common after a policy was 'tightened'), this principal can reactivate "
        "it and gain the older permissions. If the principal also holds "
        "iam:CreatePolicyVersion, the effect is full control over the policy."
    )
    remediation = (
        "Remove iam:SetDefaultPolicyVersion, or scope Resource to policies that "
        "have a single, reviewed version. Audit non-default policy versions: "
        "delete versions that are no longer needed so they cannot be reactivated."
    )

    def check(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        for kind, name in ctx.iter_principals(self.principal_types):
            eff = ctx.eff(kind, name)
            query = eff.query("iam:SetDefaultPolicyVersion")
            if not query.allowed:
                continue
            own_policies = ctx.attached_local_policy_arns(kind, name)
            wildcard = _covers_wildcard(query)
            covers_own = bool(_covered_values(query, own_policies))
            if not wildcard and not covers_own:
                continue
            can_create = eff.query("iam:CreatePolicyVersion").allowed
            severity = Severity.HIGH if can_create else Severity.MEDIUM
            notes = [_scope_note(query)]
            notes.append(
                "Also holds iam:CreatePolicyVersion: can publish and activate "
                "an arbitrary new policy version."
                if can_create
                else "Only existing versions can be activated (no "
                "iam:CreatePolicyVersion): impact depends on what older "
                "versions contain."
            )
            findings.append(
                self.make_finding(
                    ctx,
                    kind,
                    name,
                    permissions=["iam:SetDefaultPolicyVersion"],
                    evidence=_evidence(query),
                    severity=severity,
                    confidence=_confidence(query),
                    conditional=query.conditional,
                    notes=notes,
                    extras={
                        "resource_scope": "*" if wildcard else "attached-policies",
                        "also_has_create_policy_version": can_create,
                    },
                )
            )
        return findings


class _AttachRuleBase(Rule):
    """Shared logic for iam:Attach{User,Group,Role}Policy."""

    category = "escalation"
    target_kind: str = ""  # "user" | "group" | "role"

    def _self_benefiting(
        self, ctx: AnalysisContext, kind: str, name: str, covered_targets: list[str]
    ) -> bool:
        """Can the principal attach a policy so that *it* gains permissions?"""
        raise NotImplementedError

    def check(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        all_targets = {
            "user": [u.arn for u in ctx.account.users.values()],
            "group": [g.arn for g in ctx.account.groups.values()],
            "role": [r.arn for r in ctx.account.roles.values()],
        }[self.target_kind]
        local_policies = list(ctx.account.managed_policies)
        for kind, name in ctx.iter_principals(self.principal_types):
            query = ctx.eff(kind, name).query(self.required_permissions[0])
            if not query.allowed:
                continue
            wildcard = _covers_wildcard(query)
            covered_targets = _covered_values(query, all_targets)
            covered_policies = _covered_values(query, local_policies)
            # Policy-ARN scope only matters when the policy itself is
            # powerful: attaching a harmless policy escalates nobody.
            privileged_policies = [
                arn for arn in covered_policies if ctx.policy_is_privileged(arn)
            ]
            if not wildcard and not covered_targets and not privileged_policies:
                continue
            self_benefiting = wildcard or self._self_benefiting(
                ctx, kind, name, covered_targets
            )
            if self_benefiting:
                severity = Severity.HIGH
                reason = self._benefit_reason(ctx, kind, name, wildcard, covered_targets)
            elif privileged_policies:
                # Scope is a policy ARN: the principal can bind that policy to
                # a target (typically a user it controls).
                severity = Severity.HIGH
                reason = (
                    "Resource scope covers policy ARN(s) that themselves grant "
                    "admin/escalation permissions: "
                    + ", ".join(privileged_policies)
                )
            else:
                severity = Severity.MEDIUM
                reason = (
                    "Scope covers other principals only: this is a backdoor "
                    "technique (elevating somebody else), not direct "
                    "self-escalation."
                )
            findings.append(
                self.make_finding(
                    ctx,
                    kind,
                    name,
                    permissions=[self.required_permissions[0]],
                    evidence=_evidence(query),
                    severity=severity,
                    confidence=_confidence(query),
                    conditional=query.conditional,
                    notes=[_scope_note(query), reason],
                    extras={
                        "resource_scope": "*" if wildcard else "scoped",
                        "covered_targets": covered_targets,
                        "covered_local_policies": covered_policies,
                        "privileged_policies": privileged_policies,
                    },
                )
            )
        return findings

    def _benefit_reason(
        self,
        ctx: AnalysisContext,
        kind: str,
        name: str,
        wildcard: bool,
        covered_targets: list[str],
    ) -> str:
        raise NotImplementedError


class AttachUserPolicyRule(_AttachRuleBase):
    id = "IAM_ATTACH_USER_POLICY"
    title = "Attach a managed policy to an IAM user"
    severity = Severity.HIGH
    required_permissions = ["iam:AttachUserPolicy"]
    target_kind = "user"
    references = [RHINO_ESCALATION, AWS_IAM_ACTIONS]
    explanation = (
        "iam:AttachUserPolicy binds a managed policy's permissions to a user. "
        "This principal can attach an administrator policy (for example "
        "arn:aws:iam::aws:policy/AdministratorAccess) to a user it controls and "
        "immediately receive those permissions."
    )
    remediation = (
        "Remove iam:AttachUserPolicy or restrict Resource to the principal's own "
        "user ARN only if self-service attachment is required (ideally limited "
        "to non-privileged, reviewable policies). Never grant it on '*' with "
        "access to AdministratorAccess or similar policies."
    )

    def _self_benefiting(self, ctx, kind, name, covered_targets):
        own = ctx.arn(kind, name)
        return kind == "user" and own in covered_targets

    def _benefit_reason(self, ctx, kind, name, wildcard, covered_targets):
        if wildcard:
            return "Scope includes Resource: *: can attach any policy to this user."
        return "Scope includes this principal's own user ARN: can attach any policy to itself."


class AttachGroupPolicyRule(_AttachRuleBase):
    id = "IAM_ATTACH_GROUP_POLICY"
    title = "Attach a managed policy to an IAM group"
    severity = Severity.HIGH
    required_permissions = ["iam:AttachGroupPolicy"]
    target_kind = "group"
    references = [RHINO_ESCALATION, AWS_IAM_ACTIONS]
    explanation = (
        "iam:AttachGroupPolicy binds a managed policy's permissions to a group. "
        "A member of the target group receives the new permissions, so a user "
        "who can attach an administrator policy to one of their own groups gains "
        "full admin access."
    )
    remediation = (
        "Remove iam:AttachGroupPolicy or scope Resource to specific groups the "
        "principal does not belong to and never to '*' combined with access to "
        "privileged policies."
    )

    def _self_benefiting(self, ctx, kind, name, covered_targets):
        if kind == "user":
            user = ctx.account.users[name]
            own_groups = {
                g.arn for g in ctx.account.groups.values() if g.name in user.group_names
            }
            return bool(own_groups.intersection(covered_targets))
        # Roles are not group members, but covering any group still lets the
        # principal elevate that group's members (backdoor, graded below).
        return False

    def _benefit_reason(self, ctx, kind, name, wildcard, covered_targets):
        if wildcard:
            return (
                "Scope includes Resource: *: can attach any policy to any "
                "group, including this principal's own groups."
            )
        return (
            "Scope includes a group this principal belongs to: attaching a "
            "policy there elevates this principal."
        )


class AttachRolePolicyRule(_AttachRuleBase):
    id = "IAM_ATTACH_ROLE_POLICY"
    title = "Attach a managed policy to an IAM role"
    severity = Severity.HIGH
    required_permissions = ["iam:AttachRolePolicy"]
    target_kind = "role"
    references = [RHINO_ESCALATION, AWS_IAM_ACTIONS]
    explanation = (
        "iam:AttachRolePolicy binds a managed policy's permissions to a role. "
        "If the principal can also assume the target role, attaching an "
        "administrator policy to it and then assuming it yields full admin "
        "access."
    )
    remediation = (
        "Remove iam:AttachRolePolicy or scope Resource away from roles this "
        "principal can assume. Review every role that allows this principal to "
        "sts:AssumeRole - the combination is the escalation path."
    )

    def _self_benefiting(self, ctx, kind, name, covered_targets):
        assumable = _assumable_role_names(ctx, kind, name)
        target_arns = {
            ctx.account.roles[r].arn for r in assumable
        }
        return bool(target_arns.intersection(covered_targets))

    def _benefit_reason(self, ctx, kind, name, wildcard, covered_targets):
        if wildcard:
            return (
                "Scope includes Resource: *: can attach any policy to any "
                "role (including roles this principal can assume)."
            )
        assumable = _assumable_role_names(ctx, kind, name)
        named = [
            r for r in sorted(assumable) if ctx.account.roles[r].arn in covered_targets
        ]
        return f"Scope includes assumable role(s): {', '.join(named)}."


class PutUserPolicyRule(Rule):
    id = "IAM_PUT_USER_POLICY"
    title = "Write an inline policy onto an IAM user"
    severity = Severity.HIGH
    category = "escalation"
    required_permissions = ["iam:PutUserPolicy"]
    references = [RHINO_ESCALATION, AWS_IAM_ACTIONS]
    explanation = (
        "iam:PutUserPolicy replaces or creates an inline policy on a user. The "
        "policy document is chosen by the caller, so this principal can write an "
        "administrator policy onto a user it controls and receive those "
        "permissions."
    )
    remediation = (
        "Remove iam:PutUserPolicy or scope Resource to users other than the "
        "principal itself. Treat any Put*Policy permission on '*' as "
        "equivalent to admin access."
    )

    def check(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        user_arns = [u.arn for u in ctx.account.users.values()]
        for kind, name in ctx.iter_principals(self.principal_types):
            query = ctx.eff(kind, name).query("iam:PutUserPolicy")
            if not query.allowed:
                continue
            wildcard = _covers_wildcard(query)
            covered = _covered_values(query, user_arns)
            if not wildcard and not covered:
                continue
            own = kind == "user" and ctx.arn(kind, name) in covered
            self_benefiting = wildcard or own
            findings.append(
                self.make_finding(
                    ctx,
                    kind,
                    name,
                    permissions=["iam:PutUserPolicy"],
                    evidence=_evidence(query),
                    severity=Severity.HIGH if self_benefiting else Severity.MEDIUM,
                    confidence=_confidence(query),
                    conditional=query.conditional,
                    notes=[
                        _scope_note(query),
                        (
                            "Scope covers this principal's own user ARN or '*': "
                            "direct self-escalation by writing an admin inline "
                            "policy."
                            if self_benefiting
                            else "Scope covers other users only: backdoor "
                            "technique, not direct self-escalation."
                        ),
                    ],
                    extras={
                        "resource_scope": "*" if wildcard else "scoped",
                        "covered_targets": covered,
                    },
                )
            )
        return findings


class PutGroupPolicyRule(Rule):
    id = "IAM_PUT_GROUP_POLICY"
    title = "Write an inline policy onto an IAM group"
    severity = Severity.HIGH
    category = "escalation"
    required_permissions = ["iam:PutGroupPolicy"]
    references = [RHINO_ESCALATION, AWS_IAM_ACTIONS]
    explanation = (
        "iam:PutGroupPolicy replaces or creates an inline policy on a group. "
        "Every member of the group gains the new permissions, so a member who "
        "can write an administrator policy onto their own group gains full "
        "admin access."
    )
    remediation = (
        "Remove iam:PutGroupPolicy or scope Resource away from groups this "
        "principal belongs to. Never allow it on '*' for groups that hold "
        "privileged permissions."
    )

    def check(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        group_arns = [g.arn for g in ctx.account.groups.values()]
        for kind, name in ctx.iter_principals(self.principal_types):
            query = ctx.eff(kind, name).query("iam:PutGroupPolicy")
            if not query.allowed:
                continue
            wildcard = _covers_wildcard(query)
            covered = _covered_values(query, group_arns)
            if not wildcard and not covered:
                continue
            own_groups: set[str] = set()
            if kind == "user":
                user = ctx.account.users[name]
                own_groups = {
                    g.arn
                    for g in ctx.account.groups.values()
                    if g.name in user.group_names
                }
            self_benefiting = wildcard or bool(own_groups.intersection(covered))
            findings.append(
                self.make_finding(
                    ctx,
                    kind,
                    name,
                    permissions=["iam:PutGroupPolicy"],
                    evidence=_evidence(query),
                    severity=Severity.HIGH if self_benefiting else Severity.MEDIUM,
                    confidence=_confidence(query),
                    conditional=query.conditional,
                    notes=[
                        _scope_note(query),
                        (
                            "Scope covers a group this principal belongs to (or "
                            "'*'): direct self-escalation."
                            if self_benefiting
                            else "Scope covers other groups only: backdoor "
                            "technique, not direct self-escalation."
                        ),
                    ],
                    extras={
                        "resource_scope": "*" if wildcard else "scoped",
                        "covered_targets": covered,
                    },
                )
            )
        return findings


class PutRolePolicyRule(Rule):
    id = "IAM_PUT_ROLE_POLICY"
    title = "Write an inline policy onto an IAM role"
    severity = Severity.HIGH
    category = "escalation"
    required_permissions = ["iam:PutRolePolicy"]
    references = [RHINO_ESCALATION, AWS_IAM_ACTIONS]
    explanation = (
        "iam:PutRolePolicy replaces or creates an inline policy on a role. If "
        "the principal can also assume the target role, writing an "
        "administrator inline policy onto it and assuming it yields full admin "
        "access."
    )
    remediation = (
        "Remove iam:PutRolePolicy or scope Resource away from roles this "
        "principal can assume. Audit who can sts:AssumeRole each affected role."
    )

    def check(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        role_arns = [r.arn for r in ctx.account.roles.values()]
        for kind, name in ctx.iter_principals(self.principal_types):
            query = ctx.eff(kind, name).query("iam:PutRolePolicy")
            if not query.allowed:
                continue
            wildcard = _covers_wildcard(query)
            covered = _covered_values(query, role_arns)
            if not wildcard and not covered:
                continue
            assumable = _assumable_role_names(ctx, kind, name)
            assumable_arns = {ctx.account.roles[r].arn for r in assumable}
            self_benefiting = wildcard or bool(assumable_arns.intersection(covered))
            named = [
                r for r in sorted(assumable) if ctx.account.roles[r].arn in covered
            ]
            findings.append(
                self.make_finding(
                    ctx,
                    kind,
                    name,
                    permissions=["iam:PutRolePolicy"],
                    evidence=_evidence(query),
                    severity=Severity.HIGH if self_benefiting else Severity.MEDIUM,
                    confidence=_confidence(query),
                    conditional=query.conditional,
                    notes=[
                        _scope_note(query),
                        (
                            f"Scope includes assumable role(s): {', '.join(named)}."
                            if named
                            else (
                                "Scope includes Resource: *: can write inline "
                                "policies onto any role, including roles this "
                                "principal can assume."
                                if wildcard
                                else "Scope covers roles this principal cannot "
                                "assume: backdoor technique, not direct "
                                "self-escalation."
                            )
                        ),
                    ],
                    extras={
                        "resource_scope": "*" if wildcard else "scoped",
                        "covered_targets": covered,
                        "assumable_roles": sorted(assumable),
                    },
                )
            )
        return findings


class AddUserToGroupRule(Rule):
    id = "IAM_ADD_USER_TO_GROUP"
    title = "Add a user to an IAM group"
    severity = Severity.HIGH
    category = "escalation"
    required_permissions = ["iam:AddUserToGroup"]
    references = [RHINO_ESCALATION, AWS_IAM_ACTIONS]
    explanation = (
        "iam:AddUserToGroup changes group membership. A principal who can add "
        "itself to a privileged group inherits every permission that group "
        "grants. Group membership is the standard way AWS administrators grant "
        "permissions, so compromising a principal that can edit membership is "
        "usually a direct path to admin."
    )
    remediation = (
        "Remove iam:AddUserToGroup or scope Resource to specific non-privileged "
        "groups. Never grant membership editing on '*' to non-administrators, "
        "and avoid groups that combine broad permissions with editable "
        "membership."
    )

    def check(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        user_arns = [u.arn for u in ctx.account.users.values()]
        group_arns = [g.arn for g in ctx.account.groups.values()]
        privileged_groups = ctx.privileged_groups()
        for kind, name in ctx.iter_principals(self.principal_types):
            query = ctx.eff(kind, name).query("iam:AddUserToGroup")
            if not query.allowed:
                continue
            wildcard = _covers_wildcard(query)
            covered_users = _covered_values(query, user_arns)
            covered_groups = _covered_values(query, group_arns)
            if not wildcard and not covered_users and not covered_groups:
                continue
            # Self-escalation requires being able to add *oneself*: user scope
            # covering own ARN, or any group scope (one may add oneself to
            # that group).  Roles cannot be group members, so for them this
            # is only a backdoor technique.
            if kind == "user":
                self_covered = (
                    wildcard
                    or ctx.arn(kind, name) in covered_users
                    or bool(covered_groups)
                )
            else:
                self_covered = False
            others = [
                u for u in covered_users if kind != "user" or u != ctx.arn(kind, name)
            ]
            if not self_covered and not others and not covered_groups:
                continue
            if self_covered and privileged_groups:
                severity = Severity.HIGH
                reason = (
                    "Privileged group(s) exist that this principal could join: "
                    + ", ".join(privileged_groups)
                )
            elif self_covered:
                severity = Severity.MEDIUM
                reason = (
                    "No privileged groups exist in the export, so the direct "
                    "impact depends on current group permissions."
                )
            else:
                severity = Severity.MEDIUM
                reason = (
                    "This principal cannot add itself with this scope: "
                    "membership tampering only (backdoor technique)."
                )
            findings.append(
                self.make_finding(
                    ctx,
                    kind,
                    name,
                    permissions=["iam:AddUserToGroup"],
                    evidence=_evidence(query),
                    severity=severity,
                    confidence=_confidence(query),
                    conditional=query.conditional,
                    notes=[_scope_note(query), reason],
                    extras={
                        "resource_scope": "*" if wildcard else "scoped",
                        "privileged_groups": privileged_groups,
                        "covered_users": covered_users,
                        "covered_groups": covered_groups,
                    },
                )
            )
        return findings


class CreateAccessKeyRule(Rule):
    id = "IAM_CREATE_ACCESS_KEY"
    title = "Create access keys for other IAM users"
    severity = Severity.HIGH
    category = "escalation"
    required_permissions = ["iam:CreateAccessKey"]
    references = [RHINO_ESCALATION, AWS_IAM_ACTIONS]
    explanation = (
        "iam:CreateAccessKey issues a new access key pair for an IAM user. "
        "Access keys are long-lived credentials that carry exactly the victim "
        "user's permissions, so creating a key for a more-privileged user and "
        "using it from anywhere yields that user's access without needing their "
        "existing credentials."
    )
    remediation = (
        "Remove iam:CreateAccessKey or scope Resource with "
        "${aws:username} (arn:aws:iam::ACCOUNT:user/${aws:username}) so "
        "principals can only manage their own keys. Enable access-key age "
        "alerts and review IAM credential reports regularly."
    )

    def check(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        for kind, name in ctx.iter_principals(self.principal_types):
            query = ctx.eff(kind, name).query("iam:CreateAccessKey")
            if not query.allowed:
                continue
            wildcard = _covers_wildcard(query)
            user_arns = [u.arn for u in ctx.account.users.values()]
            covered = _covered_values(query, user_arns)
            own = ctx.arn(kind, name) if kind == "user" else None
            others = [arn for arn in covered if arn != own]
            if not others:
                continue  # only self (or nobody): not an escalation
            covered_names = [arn.rsplit("/", 1)[-1] for arn in others]
            privileged_targets = [
                n for n in covered_names if ctx.is_privileged("user", n)
            ]
            severity = Severity.HIGH if privileged_targets else Severity.MEDIUM
            notes = [_scope_note(query)]
            if privileged_targets:
                notes.append(
                    "Can create keys for privileged user(s): "
                    + ", ".join(privileged_targets)
                )
            else:
                notes.append(
                    "Targets are non-privileged users: impact equals those "
                    "users' current permissions."
                )
            findings.append(
                self.make_finding(
                    ctx,
                    kind,
                    name,
                    permissions=["iam:CreateAccessKey"],
                    evidence=_evidence(query),
                    severity=severity,
                    confidence=_confidence(query),
                    conditional=query.conditional,
                    notes=notes,
                    extras={
                        "resource_scope": "*" if wildcard else "scoped",
                        "covered_users": covered_names,
                        "privileged_targets": privileged_targets,
                    },
                )
            )
        return findings


class LoginProfileRule(Rule):
    id = "IAM_LOGIN_PROFILE"
    title = "Create or reset console passwords for other IAM users"
    severity = Severity.HIGH
    category = "escalation"
    required_permissions = ["iam:CreateLoginProfile", "iam:UpdateLoginProfile"]
    references = [RHINO_ESCALATION, AWS_IAM_ACTIONS]
    explanation = (
        "iam:CreateLoginProfile gives an IAM user a console password and "
        "iam:UpdateLoginProfile changes an existing one. Either lets this "
        "principal sign in to the AWS console as a more-privileged user with a "
        "password of its choosing."
    )
    remediation = (
        "Remove iam:CreateLoginProfile/iam:UpdateLoginProfile or scope them "
        "with ${aws:username} so principals only manage their own password. "
        "Require MFA for console users and alert on login-profile changes."
    )

    def check(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        for kind, name in ctx.iter_principals(self.principal_types):
            eff = ctx.eff(kind, name)
            create_q = eff.query("iam:CreateLoginProfile")
            update_q = eff.query("iam:UpdateLoginProfile")
            if create_q.allowed:
                query = create_q
                permissions = ["iam:CreateLoginProfile"]
            elif update_q.allowed:
                query = update_q
                permissions = ["iam:UpdateLoginProfile"]
            else:
                continue
            # Merge scope from both actions when both are present.
            all_refs = create_q.allows + update_q.allows
            wildcard = any(resource_covers(r.statement, "*") for r in all_refs)
            user_arns = [u.arn for u in ctx.account.users.values()]
            covered = [
                arn
                for arn in user_arns
                if any(resource_covers(r.statement, arn) for r in all_refs)
            ]
            own = ctx.arn(kind, name) if kind == "user" else None
            others = [arn for arn in covered if arn != own]
            if not others:
                continue
            if create_q.allowed and update_q.allowed:
                permissions = ["iam:CreateLoginProfile", "iam:UpdateLoginProfile"]
            covered_names = [arn.rsplit("/", 1)[-1] for arn in others]
            privileged_targets = [
                n for n in covered_names if ctx.is_privileged("user", n)
            ]
            severity = Severity.HIGH if privileged_targets else Severity.MEDIUM
            notes = [_scope_note(query)]
            if privileged_targets:
                notes.append(
                    "Can set passwords for privileged user(s): "
                    + ", ".join(privileged_targets)
                )
            else:
                notes.append(
                    "Targets are non-privileged users: impact equals those "
                    "users' current permissions."
                )
            findings.append(
                self.make_finding(
                    ctx,
                    kind,
                    name,
                    permissions=permissions,
                    evidence=_evidence(query),
                    severity=severity,
                    confidence=_confidence(query),
                    conditional=query.conditional,
                    notes=notes,
                    extras={
                        "resource_scope": "*" if wildcard else "scoped",
                        "covered_users": covered_names,
                        "privileged_targets": privileged_targets,
                    },
                )
            )
        return findings


class UpdateAssumeRolePolicyRule(Rule):
    id = "IAM_UPDATE_ASSUME_ROLE_POLICY"
    title = "Rewrite a role's trust policy, then assume the role"
    severity = Severity.HIGH
    category = "escalation"
    required_permissions = ["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"]
    references = [RHINO_ESCALATION, AWS_EVAL_LOGIC]
    explanation = (
        "iam:UpdateAssumeRolePolicy rewrites who is allowed to assume a role. "
        "Combined with sts:AssumeRole permission on the same role, this "
        "principal can add itself to the role's trust policy and then assume "
        "it, acting with everything the role can do."
    )
    remediation = (
        "Remove iam:UpdateAssumeRolePolicy or scope Resource away from roles "
        "this principal can assume. Restrict sts:AssumeRole at the same time: "
        "the pair is the escalation path, and either permission alone is not."
    )

    def check(self, ctx: AnalysisContext) -> list[Finding]:
        findings = []
        role_arns = [r.arn for r in ctx.account.roles.values()]
        for kind, name in ctx.iter_principals(self.principal_types):
            eff = ctx.eff(kind, name)
            update_q = eff.query("iam:UpdateAssumeRolePolicy")
            assume_q = eff.query("sts:AssumeRole")
            if not (update_q.allowed and assume_q.allowed):
                continue  # both permissions are required for this technique
            wildcard_update = _covers_wildcard(update_q)
            wildcard_assume = _covers_wildcard(assume_q)
            # Roles whose trust this principal can rewrite *and* for which it
            # holds the assume permission (the two halves of the technique).
            update_targets = _covered_values(update_q, role_arns)
            assume_targets = _covered_values(assume_q, role_arns)
            overlap = sorted(set(update_targets) & set(assume_targets))
            if wildcard_update and wildcard_assume:
                overlap_names = sorted(ctx.account.roles)
                severity = Severity.HIGH
                reason = (
                    "Both permissions cover Resource: *: any role in the account "
                    "(including future ones) can be re-trusted and assumed."
                )
            elif not overlap:
                continue  # scopes do not intersect: technique not usable
            else:
                overlap_names = [
                    arn.rsplit("/", 1)[-1] for arn in overlap
                ]
                privileged = [
                    n for n in overlap_names if ctx.is_privileged("role", n)
                ]
                severity = Severity.HIGH if privileged else Severity.MEDIUM
                reason = (
                    "Reachable role(s) with admin/escalation permissions: "
                    + ", ".join(privileged)
                    if privileged
                    else "Reachable role(s): "
                    + ", ".join(overlap_names)
                    + " - impact equals those roles' permissions."
                )
            conditional = update_q.conditional or assume_q.conditional
            findings.append(
                self.make_finding(
                    ctx,
                    kind,
                    name,
                    permissions=["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
                    evidence=_evidence(update_q) + _evidence(assume_q),
                    severity=severity,
                    confidence=(
                        LOW_CONFIDENCE
                        if update_q.partial_denies or assume_q.partial_denies
                        else MEDIUM_CONFIDENCE
                        if conditional
                        else HIGH_CONFIDENCE
                    ),
                    conditional=conditional,
                    notes=[
                        _scope_note(update_q),
                        _scope_note(assume_q, "sts:AssumeRole scope"),
                        reason,
                    ],
                    extras={
                        "resource_scope": "*" if wildcard_update else "scoped",
                        "overlap_roles": overlap_names,
                    },
                )
            )
        return findings


SINGLE_PERMISSION_RULES: tuple[Rule, ...] = (
    CreatePolicyVersionRule(),
    SetDefaultPolicyVersionRule(),
    AttachUserPolicyRule(),
    AttachGroupPolicyRule(),
    AttachRolePolicyRule(),
    PutUserPolicyRule(),
    PutGroupPolicyRule(),
    PutRolePolicyRule(),
    AddUserToGroupRule(),
    CreateAccessKeyRule(),
    LoginProfileRule(),
    UpdateAssumeRolePolicyRule(),
)
