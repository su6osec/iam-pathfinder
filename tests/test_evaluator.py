"""Unit tests for the policy evaluation core (iam_pathfinder.evaluator).

These cover the approximation rules that every detection rule depends on:
wildcard matching, NotAction/NotResource, explicit deny, conditions, and
group inheritance.
"""

from __future__ import annotations

from conftest import export, group, local_policy_arn, managed_policy, role, stmt, user

from iam_pathfinder.evaluator import (
    ANY_RESOURCE,
    EffectivePermissions,
    StatementRef,
    action_covers,
    build_effective_permissions,
    is_universal_allow,
    pattern_matches,
    patterns_overlap,
    resource_covers,
)
from iam_pathfinder.model import statement_from_dict


def _stmt_ref(data: dict, *, name: str = "policy", arn: str | None = None,
              origin: str = "inline") -> StatementRef:
    return StatementRef(
        statement=statement_from_dict(data),
        policy_name=name,
        policy_arn=arn,
        origin=origin,
    )


class TestPatternMatching:
    def test_exact_match(self):
        assert pattern_matches("iam:PassRole", "iam:PassRole")

    def test_service_wildcard(self):
        assert pattern_matches("iam:*", "iam:CreateUser")
        assert not pattern_matches("iam:*", "s3:GetObject")

    def test_prefix_wildcard(self):
        assert pattern_matches("iam:Create*", "iam:CreateUser")
        assert pattern_matches("iam:Create*", "iam:CreateAccessKey")
        assert not pattern_matches("iam:Create*", "iam:DeleteUser")

    def test_universal_wildcard(self):
        assert pattern_matches("*", "anything:AtAll")

    def test_single_character_wildcard(self):
        assert pattern_matches("s3:GetObjec?", "s3:GetObject")
        assert not pattern_matches("s3:GetObjec?", "s3:GetObjects")

    def test_case_insensitive(self):
        assert pattern_matches("iam:PassRole", "IAM:passrole")

    def test_no_match(self):
        assert not pattern_matches("s3:GetObject", "s3:PutObject")

    def test_arn_wildcards(self):
        arn = "arn:aws:iam::123456789012:role/Admin"
        assert pattern_matches("arn:aws:iam::123456789012:role/*", arn)
        assert pattern_matches("arn:aws:iam::*:role/*", arn)
        assert not pattern_matches("arn:aws:iam::999999999999:role/*", arn)

    def test_patterns_overlap(self):
        role_x = "arn:aws:iam::123456789012:role/x"
        assert patterns_overlap("*", role_x)
        assert patterns_overlap("arn:aws:iam::*:role/*", role_x)
        assert patterns_overlap("arn:aws:iam::123456789012:role/*", role_x)
        assert not patterns_overlap(role_x, "arn:aws:iam::123456789012:role/y")


class TestStatementMatching:
    def test_action_string_and_list(self):
        assert action_covers(statement_from_dict(stmt(action="iam:PassRole")), "iam:PassRole")
        assert action_covers(statement_from_dict(stmt(action=["s3:Get", "s3:Put"])), "s3:Put")

    def test_action_wildcard_covers_query(self):
        s = statement_from_dict(stmt(action="iam:*"))
        assert action_covers(s, "iam:CreateUser")

    def test_query_wildcard_is_not_covered_by_scoped_action(self):
        # Asking about action "*" is only satisfied by Action: "*".
        s = statement_from_dict(stmt(action="iam:CreateUser"))
        assert not action_covers(s, "*")
        assert action_covers(statement_from_dict(stmt(action="*")), "*")

    def test_not_action_inverts(self):
        s = statement_from_dict(stmt(not_action=["iam:*"], resource="*"))
        assert not action_covers(s, "iam:CreateUser")
        assert action_covers(s, "s3:GetObject")

    def test_resource_wildcard(self):
        s = statement_from_dict(stmt(action="s3:GetObject", resource="*"))
        assert resource_covers(s, "*")
        assert resource_covers(s, "arn:aws:s3:::bucket/key")

    def test_scoped_resource_does_not_cover_wildcard_query(self):
        s = statement_from_dict(stmt(action="s3:GetObject", resource="arn:aws:s3:::bucket"))
        assert not resource_covers(s, "*")
        assert resource_covers(s, "arn:aws:s3:::bucket")
        assert not resource_covers(s, "arn:aws:s3:::other")

    def test_not_resource_excludes(self):
        s = statement_from_dict(
            stmt(action="s3:*", resource="*", not_resource="arn:aws:s3:::secret")
        )
        assert not resource_covers(s, "arn:aws:s3:::secret")
        assert resource_covers(s, "arn:aws:s3:::public")
        # Wildcard resource with an exclusion is not a true Resource: "*".
        assert not resource_covers(s, "*")

    def test_missing_resource_is_lenient(self):
        s = statement_from_dict({"Effect": "Allow", "Action": "s3:GetObject"})
        assert resource_covers(s, "*")

    def test_universal_allow(self):
        assert is_universal_allow(statement_from_dict(stmt(action="*", resource="*")))
        assert not is_universal_allow(
            statement_from_dict(stmt(action="*", resource="arn:aws:s3:::*"))
        )
        conditional = statement_from_dict(
            stmt(
                action="*",
                resource="*",
                condition={"Bool": {"aws:SecureTransport": "true"}},
            )
        )
        assert not is_universal_allow(conditional)


class TestPermissionQuery:
    def _effective(self, *statements: dict) -> EffectivePermissions:
        return EffectivePermissions([_stmt_ref(s) for s in statements])

    def test_allowed(self):
        eff = self._effective(stmt(action="iam:PassRole", resource="*"))
        result = eff.query("iam:PassRole")
        assert result.allowed
        assert not result.conditional

    def test_not_allowed(self):
        eff = self._effective(stmt(action="s3:GetObject", resource="*"))
        assert eff.query("iam:PassRole").status == "not_allowed"

    def test_explicit_deny_overrides_allow(self):
        eff = self._effective(
            stmt("Allow", action="iam:PassRole", resource="*"),
            stmt("Deny", action="iam:PassRole", resource="*"),
        )
        result = eff.query("iam:PassRole")
        assert result.status == "denied"
        assert not result.allowed

    def test_deny_only_suppresses_matching_scope(self):
        eff = self._effective(
            stmt("Allow", action="iam:PassRole", resource="*"),
            stmt("Deny", action="iam:PassRole", resource="arn:aws:iam::123456789012:role/locked"),
        )
        # Query ignoring the resource: the scoped deny cannot suppress, but it
        # is surfaced as a partial deny so confidence can be lowered.
        result = eff.query("iam:PassRole", ANY_RESOURCE)
        assert result.allowed
        assert len(result.partial_denies) == 1

    def test_deny_suppresses_when_resource_matches(self):
        eff = self._effective(
            stmt("Allow", action="iam:PassRole", resource="*"),
            stmt("Deny", action="iam:PassRole", resource="arn:aws:iam::123456789012:role/locked"),
        )
        result = eff.query("iam:PassRole", "arn:aws:iam::123456789012:role/locked")
        assert result.status == "denied"
        result2 = eff.query("iam:PassRole", "arn:aws:iam::123456789012:role/open")
        assert result2.allowed

    def test_scoped_deny_does_not_block_wildcard_resource_query(self):
        eff = self._effective(
            stmt("Allow", action="iam:PassRole", resource="*"),
            stmt("Deny", action="iam:PassRole", resource="arn:aws:iam::123456789012:role/locked"),
        )
        result = eff.query("iam:PassRole", "*")
        assert result.allowed

    def test_conditional_deny_is_ignored(self):
        eff = self._effective(
            stmt("Allow", action="iam:PassRole", resource="*"),
            stmt("Deny", action="iam:PassRole", resource="*",
                 condition={"StringEquals": {"aws:SourceIp": "10.0.0.1"}}),
        )
        # We cannot evaluate the condition offline, so it must not hide the risk.
        assert eff.query("iam:PassRole").allowed

    def test_conditional_allow_marks_result_conditional(self):
        eff = self._effective(
            stmt("Allow", action="iam:PassRole", resource="*",
                 condition={"StringEquals": {"aws:SourceIp": "10.0.0.1"}}),
        )
        result = eff.query("iam:PassRole")
        assert result.allowed
        assert result.conditional

    def test_mixed_allows_one_conditional_is_conditional(self):
        # If *every* matching allow needs a condition, the result is conditional.
        eff = self._effective(
            stmt("Allow", action="s3:Get", resource="*"),
            stmt("Allow", action="s3:Get", resource="*",
                 condition={"Bool": {"aws:SecureTransport": "true"}}),
        )
        assert not eff.query("s3:Get").conditional
        only_conditional = self._effective(
            stmt("Allow", action="s3:Get", resource="*",
                 condition={"Bool": {"aws:SecureTransport": "true"}}),
        )
        assert only_conditional.query("s3:Get").conditional

    def test_not_action_allow_grants_other_actions(self):
        eff = self._effective(stmt(action=None, not_action=["iam:*"], resource="*"))
        assert eff.query("s3:GetObject").allowed
        assert not eff.query("iam:CreateUser").allowed

    def test_full_admin_detection(self):
        admin = self._effective(stmt(action="*", resource="*"))
        assert admin.is_full_admin()

    def test_full_admin_requires_unconditional(self):
        conditional = self._effective(
            stmt(action="*", resource="*", condition={"Bool": {"aws:SecureTransport": "true"}})
        )
        assert not conditional.is_full_admin()

    def test_full_admin_scoped_resource_is_not_admin(self):
        scoped = self._effective(stmt(action="*", resource="arn:aws:s3:::*"))
        assert not scoped.is_full_admin()

    def test_deny_all_negates_full_admin(self):
        eff = self._effective(
            stmt("Allow", action="*", resource="*"),
            stmt("Deny", action="*", resource="*"),
        )
        assert not eff.is_full_admin()

    def test_deny_not_action_negates_full_admin(self):
        # Deny everything except IAM => not full admin any more.
        eff = self._effective(
            stmt("Allow", action="*", resource="*"),
            stmt("Deny", not_action=["iam:*"], resource="*"),
        )
        assert not eff.is_full_admin()


class TestEffectivePermissionBuilding:
    def test_user_gets_attached_managed_policy(self):
        from iam_pathfinder.parser import parse_export

        data = export(
            users=[user("alice", attached=["ReadOnly"])],
            policies=[managed_policy("ReadOnly", stmt(action="s3:GetObject", resource="*"))],
        )
        account = parse_export(data).account
        eff = build_effective_permissions(account)
        assert eff["user:alice"].query("s3:GetObject").allowed

    def test_user_inherits_group_policies(self):
        from iam_pathfinder.parser import parse_export

        data = export(
            users=[user("alice", groups=["devs"])],
            groups=[group("devs", attached=["GroupPower"])],
            policies=[managed_policy("GroupPower", stmt(action="dynamodb:PutItem", resource="*"))],
        )
        eff = build_effective_permissions(parse_export(data).account)
        result = eff["user:alice"].query("dynamodb:PutItem")
        assert result.allowed
        # Provenance must show the group so findings can explain inheritance.
        assert result.allows[0].via_group == "devs"
        assert 'group "devs"' in result.allows[0].source_label

    def test_user_inherits_group_inline_policy(self):
        from iam_pathfinder.parser import parse_export

        group_inline = [
            ("gp", {"Statement": [stmt(action="ec2:StartInstances", resource="*")]})
        ]
        data = export(
            users=[user("alice", groups=["devs"])],
            groups=[group("devs", inline=group_inline)],
        )
        eff = build_effective_permissions(parse_export(data).account)
        assert eff["user:alice"].query("ec2:StartInstances").allowed

    def test_role_does_not_inherit_trust_policy(self):
        # The trust policy grants *others* the ability to assume the role; it
        # is not a permission of the role itself.
        from iam_pathfinder.parser import parse_export

        data = export(
            roles=[role("app", trust={
                "Statement": [stmt("Allow", Principal={"AWS": "*"}, Resource="*")]
            })]
        )
        eff = build_effective_permissions(parse_export(data).account)
        assert eff["role:app"].refs == []

    def test_unresolved_attachment_is_skipped_not_crashing(self):
        from iam_pathfinder.parser import parse_export

        data = export(users=[{
            "UserName": "alice",
            "Arn": "arn:aws:iam::123456789012:user/alice",
            "AttachedManagedPolicies": [
                {"PolicyName": "Gone", "PolicyArn": local_policy_arn("Gone")}
            ],
        }])
        parsed = parse_export(data)
        eff = build_effective_permissions(parsed.account)
        assert parsed.unresolved_policy_arns == [local_policy_arn("Gone")]
        assert eff["user:alice"].refs == []

    def test_deny_flows_through_group_inheritance(self):
        from iam_pathfinder.parser import parse_export

        data = export(
            users=[user("alice", groups=["devs"])],
            groups=[group("devs", inline=[("deny-all", {"Statement": [
                stmt("Deny", action="s3:DeleteObject", resource="*")
            ]})])],
        )
        eff = build_effective_permissions(parse_export(data).account)
        result = eff["user:alice"].query("s3:DeleteObject")
        assert result.status == "denied"
