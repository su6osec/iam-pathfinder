"""Tests for the ``get-account-authorization-details`` parser."""

from __future__ import annotations

import json

import pytest
from conftest import (
    export,
    group,
    local_policy_arn,
    managed_policy,
    policy_document,
    role,
    stmt,
    user,
)

from iam_pathfinder.parser import ParseError, load_export, parse_export, parse_policy_document


class TestPolicyDocumentParsing:
    def test_dict_document(self):
        doc = {"Version": "2012-10-17", "Statement": [stmt(action="s3:GetObject", resource="*")]}
        statements = parse_policy_document(doc, context="test")
        assert len(statements) == 1
        assert statements[0].actions == ("s3:GetObject",)

    def test_url_encoded_document(self):
        from urllib.parse import quote

        raw = json.dumps(
            {"Version": "2012-10-17", "Statement": [stmt(action="iam:PassRole", resource="*")]}
        )
        statements = parse_policy_document(quote(raw), context="test")
        assert statements[0].actions == ("iam:PassRole",)

    def test_statement_may_be_single_object(self):
        doc = {"Statement": stmt(action="s3:ListBucket", resource="*")}
        statements = parse_policy_document(doc, context="test")
        assert len(statements) == 1

    def test_action_as_string_and_list(self):
        doc = {"Statement": [
            stmt(action="s3:GetObject", resource="*"),
            stmt(action=["s3:PutObject", "s3:DeleteObject"], resource="*"),
        ]}
        statements = parse_policy_document(doc, context="test")
        assert statements[0].actions == ("s3:GetObject",)
        assert statements[1].actions == ("s3:PutObject", "s3:DeleteObject")

    def test_invalid_json_raises(self):
        with pytest.raises(ParseError, match="not valid JSON"):
            parse_policy_document("%%%not-json%%%", context="test policy")

    def test_non_object_document_raises(self):
        with pytest.raises(ParseError, match="must be a JSON object"):
            parse_policy_document([1, 2, 3], context="test policy")


class TestExportParsing:
    def test_parses_all_entity_types(self):
        data = export(
            users=[user("alice", attached=["ReadOnly"])],
            groups=[group("devs")],
            roles=[role("app")],
            policies=[managed_policy("ReadOnly", stmt(action="s3:GetObject", resource="*"))],
        )
        parsed = parse_export(data)
        assert set(parsed.account.users) == {"alice"}
        assert set(parsed.account.groups) == {"devs"}
        assert set(parsed.account.roles) == {"app"}
        assert local_policy_arn("ReadOnly") in parsed.account.managed_policies
        assert parsed.account.account_id == "123456789012"
        assert parsed.unresolved_policy_arns == []

    def test_group_list_is_group_names(self):
        data = export(
            users=[user("alice", groups=["devs", "ops"])],
            groups=[group("devs"), group("ops")],
        )
        parsed = parse_export(data)
        assert parsed.account.users["alice"].group_names == ("devs", "ops")

    def test_group_list_entries_may_be_objects(self):
        # Defensive: tolerate tools that rewrote names as objects.
        u = user("alice")
        u["GroupList"] = [{"GroupName": "devs"}]
        parsed = parse_export(export(users=[u], groups=[group("devs")]))
        assert parsed.account.users["alice"].group_names == ("devs",)

    def test_default_policy_version_is_used(self):
        policy = managed_policy(
            "Multi", stmt(action="s3:GetObject", resource="*"), default_version="v2"
        )
        # Add a non-default v1 with a different statement.
        policy["PolicyVersionList"].insert(
            0,
            {
                "VersionId": "v1",
                "IsDefaultVersion": False,
                "Document": policy_document(stmt(action="s3:PutObject", resource="*")),
                "CreateDate": "2024-01-01T00:00:00+00:00",
            },
        )
        parsed = parse_export(export(policies=[policy]))
        doc = parsed.account.resolve_policy(local_policy_arn("Multi"))
        assert doc is not None
        assert doc.statements[0].actions == ("s3:GetObject",)

    def test_unresolved_attachment_is_reported(self):
        data = export(
            users=[{
                "UserName": "alice",
                "Arn": "arn:aws:iam::123456789012:user/alice",
                "AttachedManagedPolicies": [
                    {
                        "PolicyName": "Missing",
                        "PolicyArn": "arn:aws:iam::123456789012:policy/Missing",
                    }
                ],
            }]
        )
        parsed = parse_export(data)
        assert parsed.unresolved_policy_arns == ["arn:aws:iam::123456789012:policy/Missing"]

    def test_role_trust_policy_is_parsed(self):
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                stmt("Allow", Principal={"AWS": "arn:aws:iam::999999999999:root"}, Resource="*")
            ],
        }
        parsed = parse_export(export(roles=[role("app", trust=trust)]))
        trust_stmt = parsed.account.roles["app"].trust_policy.statements[0]
        assert trust_stmt.raw["Principal"]["AWS"] == "arn:aws:iam::999999999999:root"

    def test_missing_lists_are_empty(self):
        parsed = parse_export({})
        assert parsed.account.users == {}
        assert parsed.account.roles == {}

    def test_rejects_non_dict_input(self):
        with pytest.raises(ParseError, match="JSON object"):
            parse_export([1, 2])

    def test_rejects_dict_without_iam_keys(self):
        with pytest.raises(ParseError, match="does not look like"):
            parse_export({"foo": "bar"})

    def test_load_export_from_file(self, tmp_path):
        path = tmp_path / "export.json"
        path.write_text(json.dumps(export(users=[user("alice")])), encoding="utf-8")
        parsed = load_export(path)
        assert "alice" in parsed.account.users

    def test_load_export_invalid_json(self, tmp_path):
        path = tmp_path / "broken.json"
        path.write_text("{not json", encoding="utf-8")
        with pytest.raises(ParseError, match="not valid JSON"):
            load_export(path)

    def test_load_export_missing_file(self, tmp_path):
        with pytest.raises(ParseError, match="Cannot read"):
            load_export(tmp_path / "nope.json")
