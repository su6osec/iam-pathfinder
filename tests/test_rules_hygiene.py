"""Behaviour tests for combination (PassRole) and hygiene rules."""

from __future__ import annotations

from conftest import export, group, managed_policy, role, stmt, user, user_arn

from iam_pathfinder.analyzer import analyze_account
from iam_pathfinder.parser import parse_export
from iam_pathfinder.rules import Severity

ACCOUNT = "123456789012"


def _analyze(data: dict):
    return analyze_account(parse_export(data).account)[1]


def _by_rule(findings, rule_id: str):
    return [f for f in findings if f.rule_id == rule_id]


class TestPassRoleGrading:
    def _pairing_export(self, pass_resource: str, *, admin_role: bool) -> dict:
        return export(
            users=[
                user(
                    "alice",
                    inline=[("p", {"Statement": [
                        stmt(
                            action=["iam:PassRole", "ec2:RunInstances"],
                            resource=pass_resource,
                        )
                    ]})],
                )
            ],
            roles=[
                role(
                    "app",
                    attached=["AdministratorAccess"] if admin_role else ["ReadOnlyTools"],
                )
            ],
            policies=[
                managed_policy("AdministratorAccess", stmt(action="*", resource="*")),
                managed_policy("ReadOnlyTools", stmt(action="s3:GetObject", resource="*")),
            ],
        )

    def test_wildcard_pass_role_with_privileged_role_is_high(self):
        findings = _by_rule(_analyze(self._pairing_export("*", admin_role=True)),
                            "PASSROLE_EC2_RUNINSTANCES")
        assert findings[0].severity == Severity.HIGH
        assert findings[0].extras["privileged_roles"] == ["app"]

    def test_wildcard_pass_role_without_privileged_role_is_medium(self):
        findings = _by_rule(
            _analyze(self._pairing_export("*", admin_role=False)),
            "PASSROLE_EC2_RUNINSTANCES",
        )
        assert findings[0].severity == Severity.MEDIUM

    def test_scoped_pass_role_to_privileged_role_is_high(self):
        findings = _by_rule(
            _analyze(
                self._pairing_export(
                    f"arn:aws:iam::{ACCOUNT}:role/app", admin_role=True
                )
            ),
            "PASSROLE_EC2_RUNINSTANCES",
        )
        assert findings[0].severity == Severity.HIGH

    def test_wildcard_rule_skipped_when_pairing_applies(self):
        data = export(
            users=[
                user(
                    "alice",
                    inline=[("p", {"Statement": [
                        stmt(
                            action=["iam:PassRole", "ec2:RunInstances"],
                            resource="*",
                        )
                    ]})],
                )
            ],
            roles=[role("app")],
        )
        findings = _analyze(data)
        assert _by_rule(findings, "PASSROLE_WILDCARD") == []
        assert _by_rule(findings, "PASSROLE_EC2_RUNINSTANCES")

    def test_lambda_rule_needs_all_three_actions(self):
        data = export(
            users=[
                user(
                    "alice",
                    inline=[("p", {"Statement": [
                        stmt(
                            action=["iam:PassRole", "lambda:CreateFunction"],
                            resource="*",
                        )
                    ]})],
                )
            ],
            roles=[role("app")],
        )
        findings = _analyze(data)
        assert _by_rule(findings, "PASSROLE_LAMBDA_CREATE_INVOKE") == []
        # ... but the wildcard PassRole rule still reports the bare permission.
        assert _by_rule(findings, "PASSROLE_WILDCARD")


class TestServiceWildcard:
    def test_iam_wildcard_is_high(self):
        data = export(
            users=[
                user("alice", inline=[("p", {"Statement": [
                    stmt(action="iam:*", resource="*")
                ]})])
            ]
        )
        findings = _by_rule(_analyze(data), "SERVICE_WILDCARD")
        assert findings[0].severity == Severity.HIGH
        assert findings[0].extras["service"] == "iam"

    def test_other_service_wildcard_is_medium(self):
        data = export(
            users=[
                user("alice", inline=[("p", {"Statement": [
                    stmt(action="s3:*", resource="*")
                ]})])
            ]
        )
        findings = _by_rule(_analyze(data), "SERVICE_WILDCARD")
        assert findings[0].severity == Severity.MEDIUM

    def test_prefix_wildcard_is_not_service_wide(self):
        # iam:Create* is a prefix wildcard, not the whole service.
        data = export(
            users=[
                user("alice", inline=[("p", {"Statement": [
                    stmt(action="iam:Create*", resource="*")
                ]})])
            ]
        )
        assert _by_rule(_analyze(data), "SERVICE_WILDCARD") == []

    def test_admin_action_star_is_not_double_reported(self):
        data = export(
            users=[
                user("alice", inline=[("p", {"Statement": [
                    stmt(action="*", resource="*")
                ]})])
            ]
        )
        findings = _analyze(data)
        assert _by_rule(findings, "SERVICE_WILDCARD") == []
        assert len(_by_rule(findings, "FULL_ADMIN")) == 1


class TestFullAdmin:
    def test_severity_by_principal_type(self):
        data = export(
            users=[user("alice", inline=[("p", {"Statement": [
                stmt(action="*", resource="*")
            ]})])],
            groups=[group("admins", inline=[("g", {"Statement": [
                stmt(action="*", resource="*")
            ]})])],
            roles=[role("admin", inline=[("r", {"Statement": [
                stmt(action="*", resource="*")
            ]})])],
        )
        findings = _by_rule(_analyze(data), "FULL_ADMIN")
        by_type = {f.principal_type: f.severity for f in findings}
        assert by_type["user"] == Severity.CRITICAL
        assert by_type["group"] == Severity.HIGH
        assert by_type["role"] == Severity.HIGH

    def test_deny_all_negates_full_admin(self):
        data = export(
            users=[
                user("alice", inline=[("p", {"Statement": [
                    stmt(action="*", resource="*"),
                    stmt("Deny", action="*", resource="*"),
                ]})])
            ]
        )
        assert _by_rule(_analyze(data), "FULL_ADMIN") == []

    def test_conditional_admin_is_not_reported_as_standing_admin(self):
        data = export(
            users=[
                user("alice", inline=[("p", {"Statement": [
                    stmt(
                        action="*",
                        resource="*",
                        condition={"Bool": {"aws:SecureTransport": "true"}},
                    )
                ]})])
            ]
        )
        assert _by_rule(_analyze(data), "FULL_ADMIN") == []


class TestAssumeRoleWildcard:
    def test_high_when_a_privileged_role_trusts_the_principal(self):
        data = export(
            users=[
                user("alice", inline=[("p", {"Statement": [
                    stmt(action="sts:AssumeRole", resource="*")
                ]})])
            ],
            roles=[
                role(
                    "admin",
                    trust={"Statement": [
                        stmt("Allow", Principal={"AWS": user_arn("alice")}, Resource="*")
                    ]},
                    attached=["AdministratorAccess"],
                )
            ],
            policies=[managed_policy("AdministratorAccess", stmt(action="*", resource="*"))],
        )
        findings = _by_rule(_analyze(data), "STS_ASSUMEROLE_WILDCARD")
        assert findings[0].severity == Severity.HIGH
        assert findings[0].extras["privileged_roles"] == ["admin"]

    def test_medium_when_no_role_trusts_the_principal(self):
        data = export(
            users=[
                user("alice", inline=[("p", {"Statement": [
                    stmt(action="sts:AssumeRole", resource="*")
                ]})])
            ],
            roles=[role("app")],
        )
        findings = _by_rule(_analyze(data), "STS_ASSUMEROLE_WILDCARD")
        assert findings[0].severity == Severity.MEDIUM
        assert findings[0].extras["trusting_roles"] == []


class TestTrustRules:
    def _role_export(self, trust_stmt: dict) -> dict:
        return export(
            roles=[
                role(
                    "app",
                    trust={"Statement": [trust_stmt]},
                    attached=["ReadOnlyTools"],
                )
            ],
            policies=[
                managed_policy("ReadOnlyTools", stmt(action="s3:GetObject", resource="*"))
            ],
        )

    def test_public_trust_without_condition_is_reported(self):
        data = self._role_export(stmt("Allow", Principal="*", Resource="*"))
        findings = _by_rule(_analyze(data), "TRUST_POLICY_PUBLIC")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_public_trust_with_condition_is_not_reported(self):
        # Documented assumption: any Condition is treated as potentially
        # restricting (we cannot evaluate condition values offline).
        data = self._role_export(
            stmt(
                "Allow",
                Principal="*",
                Resource="*",
                condition={"StringEquals": {"aws:PrincipalOrgID": "o-example"}},
            )
        )
        assert _by_rule(_analyze(data), "TRUST_POLICY_PUBLIC") == []

    def test_external_specific_role_arn_is_cross_account(self):
        data = self._role_export(
            stmt(
                "Allow",
                Principal={"AWS": "arn:aws:iam::999999999999:role/ci-deploy"},
                Resource="*",
            )
        )
        findings = _by_rule(_analyze(data), "TRUST_POLICY_CROSS_ACCOUNT")
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM  # role itself is read-only

    def test_external_id_condition_suppresses_cross_account_finding(self):
        data = self._role_export(
            stmt(
                "Allow",
                Principal={"AWS": "arn:aws:iam::999999999999:root"},
                Resource="*",
                condition={"StringEquals": {"sts:ExternalId": "id-123"}},
            )
        )
        assert _by_rule(_analyze(data), "TRUST_POLICY_CROSS_ACCOUNT") == []

    def test_same_account_specific_principal_is_not_reported(self):
        data = self._role_export(
            stmt("Allow", Principal={"AWS": user_arn("alice")}, Resource="*")
        )
        findings = _analyze(data)
        assert _by_rule(findings, "TRUST_POLICY_CROSS_ACCOUNT") == []
        assert _by_rule(findings, "TRUST_POLICY_ACCOUNT_ROOT") == []
        assert _by_rule(findings, "TRUST_POLICY_PUBLIC") == []

    def test_same_account_root_is_informational(self):
        data = self._role_export(
            stmt(
                "Allow",
                Principal={"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                Resource="*",
            )
        )
        findings = _by_rule(_analyze(data), "TRUST_POLICY_ACCOUNT_ROOT")
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_bare_account_id_is_treated_as_root(self):
        data = self._role_export(
            stmt("Allow", Principal={"AWS": ACCOUNT}, Resource="*")
        )
        findings = _by_rule(_analyze(data), "TRUST_POLICY_ACCOUNT_ROOT")
        assert len(findings) == 1
