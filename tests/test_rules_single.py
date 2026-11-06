"""Behaviour tests for single-permission escalation rules.

Beyond the fixture contract (test_rules_fixtures.py), these pin down the
context-sensitive severity grading, the admin-skip policy and the
conditional/partial-deny confidence handling.
"""

from __future__ import annotations

from conftest import export, group, managed_policy, role, stmt, user, user_arn

from iam_pathfinder.analyzer import analyze_account
from iam_pathfinder.parser import parse_export
from iam_pathfinder.rules import Severity

ACCOUNT = "123456789012"


def _analyze(data: dict):
    parsed = parse_export(data)
    return analyze_account(parsed.account)


def _by_rule(findings, rule_id: str):
    return [f for f in findings if f.rule_id == rule_id]


class TestCreatePolicyVersionScope:
    def test_scoped_to_own_attached_policy_is_detected(self):
        # The subtle case: Resource is one specific policy, but that policy is
        # attached to the attacker - still a direct escalation.
        data = export(
            users=[user("alice", attached=["TeamPolicy"])],
            policies=[
                managed_policy(
                    "TeamPolicy",
                    stmt(
                        action="iam:CreatePolicyVersion",
                        resource=f"arn:aws:iam::{ACCOUNT}:policy/TeamPolicy",
                    ),
                )
            ],
        )
        findings = _by_rule(_analyze(data)[1], "IAM_CREATE_POLICY_VERSION")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_scoped_to_unattached_policy_is_not_detected(self):
        data = export(
            users=[user("alice", attached=["ReadOnly"])],
            policies=[
                managed_policy(
                    "ReadOnly",
                    stmt(
                        action="iam:CreatePolicyVersion",
                        resource=f"arn:aws:iam::{ACCOUNT}:policy/SomeoneElses",
                    ),
                ),
                managed_policy("SomeoneElses", stmt(action="s3:GetObject", resource="*")),
            ],
        )
        assert _by_rule(_analyze(data)[1], "IAM_CREATE_POLICY_VERSION") == []


class TestSetDefaultPolicyVersionSeverity:
    def test_without_create_is_medium(self):
        data = export(
            users=[
                user(
                    "alice",
                    inline=[("p", {"Statement": [
                        stmt(action="iam:SetDefaultPolicyVersion", resource="*")
                    ]})],
                )
            ]
        )
        findings = _by_rule(_analyze(data)[1], "IAM_SET_DEFAULT_POLICY_VERSION")
        assert findings[0].severity == Severity.MEDIUM

    def test_with_create_is_high(self):
        data = export(
            users=[
                user(
                    "alice",
                    inline=[("p", {"Statement": [
                        stmt(
                            action=["iam:SetDefaultPolicyVersion", "iam:CreatePolicyVersion"],
                            resource="*",
                        )
                    ]})],
                )
            ]
        )
        findings = _by_rule(_analyze(data)[1], "IAM_SET_DEFAULT_POLICY_VERSION")
        assert findings[0].severity == Severity.HIGH
        assert findings[0].extras["also_has_create_policy_version"] is True


class TestAddUserToGroupScope:
    def test_scoped_to_a_real_group_is_self_escalation(self):
        # Resource names a group (not the user): the attacker can still add
        # *itself* to that group, so the rule must fire.
        data = export(
            users=[
                user(
                    "alice",
                    inline=[("p", {"Statement": [
                        stmt(
                            action="iam:AddUserToGroup",
                            resource=f"arn:aws:iam::{ACCOUNT}:group/admins",
                        )
                    ]})],
                )
            ],
            groups=[group("admins", attached=["AdministratorAccess"])],
            policies=[managed_policy("AdministratorAccess", stmt(action="*", resource="*"))],
        )
        findings = _by_rule(_analyze(data)[1], "IAM_ADD_USER_TO_GROUP")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH  # privileged group exists

    def test_without_privileged_group_is_medium(self):
        data = export(
            users=[user("alice", inline=[("p", {"Statement": [
                stmt(action="iam:AddUserToGroup", resource="*")
            ]})])],
            groups=[group("devs")],
        )
        findings = _by_rule(_analyze(data)[1], "IAM_ADD_USER_TO_GROUP")
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM


class TestCredentialRules:
    def test_create_access_key_on_non_privileged_user_is_medium(self):
        data = export(
            users=[
                user("alice", inline=[("p", {"Statement": [
                    stmt(
                        action="iam:CreateAccessKey",
                        resource=f"arn:aws:iam::{ACCOUNT}:user/carol",
                    )
                ]})]),
                user("carol"),  # no permissions
            ]
        )
        findings = _by_rule(_analyze(data)[1], "IAM_CREATE_ACCESS_KEY")
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_login_profile_reports_both_actions_when_both_present(self):
        data = export(
            users=[
                user("alice", inline=[("p", {"Statement": [
                    stmt(
                        action=["iam:CreateLoginProfile", "iam:UpdateLoginProfile"],
                        resource=f"arn:aws:iam::{ACCOUNT}:user/bob",
                    )
                ]})]),
                user("bob"),
            ]
        )
        findings = _by_rule(_analyze(data)[1], "IAM_LOGIN_PROFILE")
        assert findings[0].permissions == [
            "iam:CreateLoginProfile",
            "iam:UpdateLoginProfile",
        ]


class TestAdminSkipPolicy:
    def test_admin_principal_gets_no_escalation_findings(self):
        # A full admin holding escalation permissions is not "escalating" -
        # the FULL_ADMIN finding covers them instead.  Hygiene findings (also
        # reported for admins) are filtered by category here.
        from iam_pathfinder.rules import get_rule

        data = export(
            users=[
                user(
                    "rootish",
                    inline=[("p", {"Statement": [
                        stmt(action=["*", "iam:AttachUserPolicy"], resource="*")
                    ]})],
                )
            ]
        )
        _ctx, findings = _analyze(data)
        assert any(f.rule_id == "FULL_ADMIN" for f in findings)
        escalation = [
            f
            for f in findings
            if get_rule(f.rule_id).category in ("escalation", "combination")
        ]
        assert escalation == []

    def test_non_admin_with_same_permissions_still_reported(self):
        data = export(
            users=[
                user(
                    "alice",
                    inline=[("p", {"Statement": [
                        stmt(action="iam:AttachUserPolicy", resource="*")
                    ]})],
                )
            ]
        )
        _ctx, findings = _analyze(data)
        assert _by_rule(findings, "IAM_ATTACH_USER_POLICY")


class TestConfidenceHandling:
    def test_conditional_allow_is_flagged_and_lowered(self):
        data = export(
            users=[
                user("alice", inline=[("p", {"Statement": [
                    stmt(
                        action="iam:CreateAccessKey",
                        resource=f"arn:aws:iam::{ACCOUNT}:user/bob",
                        condition={"StringEquals": {"aws:SourceIp": "10.0.0.0/8"}},
                    )
                ]})]),
                user("bob"),
            ]
        )
        findings = _by_rule(_analyze(data)[1], "IAM_CREATE_ACCESS_KEY")
        assert findings[0].conditional is True
        assert findings[0].confidence == "medium"
        assert any("Conditional" in note for note in findings[0].notes)

    def test_partial_deny_lowers_confidence_to_low(self):
        # Allow on *, explicit Deny scoped to bob only: the permission still
        # exists (for other users) but scope is uncertain.
        data = export(
            users=[
                user(
                    "alice",
                    inline=[("p", {"Statement": [
                        stmt(action="iam:CreateAccessKey", resource="*"),
                        stmt(
                            "Deny",
                            action="iam:CreateAccessKey",
                            resource=f"arn:aws:iam::{ACCOUNT}:user/bob",
                        ),
                    ]})],
                ),
                user("bob"),
                user("carol"),
            ]
        )
        findings = _by_rule(_analyze(data)[1], "IAM_CREATE_ACCESS_KEY")
        assert len(findings) == 1
        assert findings[0].confidence == "low"
        assert any("Deny" in note for note in findings[0].notes)

    def test_explicit_deny_suppresses_the_finding(self):
        data = export(
            users=[
                user(
                    "alice",
                    inline=[("p", {"Statement": [
                        stmt(action="iam:CreateAccessKey", resource="*"),
                        stmt("Deny", action="iam:CreateAccessKey", resource="*"),
                    ]})],
                ),
                user("bob"),
            ]
        )
        assert _by_rule(_analyze(data)[1], "IAM_CREATE_ACCESS_KEY") == []


class TestAssumeRoleCombination:
    def test_update_without_assume_role_permission_is_not_reported(self):
        data = export(
            roles=[
                role(
                    "app",
                    trust={
                        "Statement": [
                            stmt("Allow", Principal={"AWS": user_arn("alice")}, Resource="*")
                        ],
                    },
                )
            ],
            users=[
                user("alice", inline=[("p", {"Statement": [
                    stmt(
                        action="iam:UpdateAssumeRolePolicy",
                        resource=f"arn:aws:iam::{ACCOUNT}:role/app",
                    )
                ]})])
            ],
        )
        findings = _analyze(data)[1]
        assert _by_rule(findings, "IAM_UPDATE_ASSUME_ROLE_POLICY") == []

    def test_overlapping_scopes_are_reported(self):
        data = export(
            roles=[
                role(
                    "app",
                    trust={
                        "Statement": [
                            stmt("Allow", Principal={"AWS": user_arn("alice")}, Resource="*")
                        ],
                    },
                )
            ],
            users=[
                user("alice", inline=[("p", {"Statement": [
                    stmt(
                        action=["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
                        resource=f"arn:aws:iam::{ACCOUNT}:role/app",
                    )
                ]})])
            ],
        )
        findings = _by_rule(_analyze(data)[1], "IAM_UPDATE_ASSUME_ROLE_POLICY")
        assert len(findings) == 1
        assert findings[0].extras["overlap_roles"] == ["app"]
