"""Shared helpers for building synthetic account exports in tests.

All data is synthetic: account 123456789012 only.
"""

from __future__ import annotations

import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"
EXAMPLE = Path(__file__).parent.parent / "examples" / "vulnerable-account.json"

ACCOUNT_ID = "123456789012"


def user_arn(name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT_ID}:user/{name}"


def role_arn(name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT_ID}:role/{name}"


def group_arn(name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT_ID}:group/{name}"


def local_policy_arn(name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT_ID}:policy/{name}"


def stmt(effect: str = "Allow", action: object = None, resource: object = None,
         condition: dict | None = None, not_action: object = None,
         not_resource: object = None, **extra: object) -> dict:
    """Build a raw policy statement."""
    data: dict = {"Effect": effect}
    if action is not None:
        data["Action"] = action
    if resource is not None:
        data["Resource"] = resource
    if not_action is not None:
        data["NotAction"] = not_action
    if not_resource is not None:
        data["NotResource"] = not_resource
    if condition is not None:
        data["Condition"] = condition
    data.update(extra)
    return data


def policy_document(*statements: dict) -> dict:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def managed_policy(name: str, *statements: dict, default_version: str = "v1") -> dict:
    """A local managed policy entry as found under ``Policies``."""
    return {
        "PolicyName": name,
        "PolicyId": f"ANPA{abs(hash(name)) % 10**12:012d}",
        "Arn": local_policy_arn(name),
        "Path": "/",
        "DefaultVersionId": default_version,
        "AttachmentCount": 1,
        "IsAttachable": True,
        "CreateDate": "2024-01-01T00:00:00+00:00",
        "PolicyVersionList": [
            {
                "VersionId": default_version,
                "IsDefaultVersion": True,
                "Document": policy_document(*statements),
                "CreateDate": "2024-01-01T00:00:00+00:00",
            }
        ],
    }


def user(name: str, *, groups: list[str] | None = None, inline: list[dict] | None = None,
         attached: list[str] | None = None) -> dict:
    return {
        "UserName": name,
        "UserId": f"AIDA{abs(hash(name)) % 10**12:012d}",
        "Arn": user_arn(name),
        "Path": "/",
        "CreateDate": "2024-01-01T00:00:00+00:00",
        "GroupList": groups or [],
        "UserPolicyList": [
            {"PolicyName": n, "PolicyDocument": d} for n, d in (inline or [])
        ],
        "AttachedManagedPolicies": [
            {"PolicyName": n, "PolicyArn": local_policy_arn(n)} for n in (attached or [])
        ],
    }


def group(
    name: str, *, inline: list[dict] | None = None, attached: list[str] | None = None
) -> dict:
    return {
        "GroupName": name,
        "GroupId": f"AGPA{abs(hash(name)) % 10**12:012d}",
        "Arn": group_arn(name),
        "Path": "/",
        "CreateDate": "2024-01-01T00:00:00+00:00",
        "GroupPolicyList": [
            {"PolicyName": n, "PolicyDocument": d} for n, d in (inline or [])
        ],
        "AttachedManagedPolicies": [
            {"PolicyName": n, "PolicyArn": local_policy_arn(n)} for n in (attached or [])
        ],
    }


def role(name: str, *, trust: dict | None = None, inline: list[dict] | None = None,
         attached: list[str] | None = None) -> dict:
    return {
        "RoleName": name,
        "RoleId": f"AROA{abs(hash(name)) % 10**12:012d}",
        "Arn": role_arn(name),
        "Path": "/",
        "CreateDate": "2024-01-01T00:00:00+00:00",
        "AssumeRolePolicyDocument": trust
        or policy_document(
            stmt("Allow", Principal={"AWS": user_arn("nobody")}, Resource="*")
        ),
        "RolePolicyList": [
            {"PolicyName": n, "PolicyDocument": d} for n, d in (inline or [])
        ],
        "AttachedManagedPolicies": [
            {"PolicyName": n, "PolicyArn": local_policy_arn(n)} for n in (attached or [])
        ],
    }


def export(*, users: list[dict] | None = None, groups: list[dict] | None = None,
           roles: list[dict] | None = None, policies: list[dict] | None = None) -> dict:
    return {
        "UserDetailList": users or [],
        "GroupDetailList": groups or [],
        "RoleDetailList": roles or [],
        "Policies": policies or [],
    }


def load_fixture(category: str, rule_id: str) -> dict:
    """Load ``tests/fixtures/<category>/<rule_id>.json``."""
    path = FIXTURES / category / f"{rule_id}.json"
    return json.loads(path.read_text(encoding="utf-8"))
