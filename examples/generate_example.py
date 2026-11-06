#!/usr/bin/env python3
"""Generate ``examples/vulnerable-account.json``.

The example is 100% synthetic: account ``123456789012`` only, no real
identifiers, no data from any AWS account.  Re-run this script after changing
the example:

    python examples/generate_example.py

The result is an export shaped like the output of::

    aws iam get-account-authorization-details
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

ACCOUNT = "123456789012"
OUT = Path(__file__).parent / "vulnerable-account.json"


def user_arn(name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT}:user/{name}"


def role_arn(name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT}:role/{name}"


def group_arn(name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT}:group/{name}"


def policy_arn(name: str) -> str:
    return f"arn:aws:iam::{ACCOUNT}:policy/{name}"


# AWS-managed policies keep their real ARNs in the export; attachments must
# point at exactly the ARN that appears under "Policies".
AWS_MANAGED = {
    "AdministratorAccess": "arn:aws:iam::aws:policy/AdministratorAccess",
}


def attachment_arn(name: str) -> str:
    return AWS_MANAGED.get(name, policy_arn(name))


def doc(*statements: dict) -> dict:
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(actions, resources, **extra) -> dict:
    statement = {
        "Effect": "Allow",
        "Resource": resources if isinstance(resources, list) else [resources],
    }
    if "NotAction" in extra:
        statement["NotAction"] = extra.pop("NotAction")
    else:
        statement["Action"] = actions if isinstance(actions, list) else [actions]
    statement.update(extra)
    return statement


def _id(prefix: str, name: str) -> str:
    """Deterministic synthetic id (stable across runs, unlike hash())."""
    digest = hashlib.sha256(name.encode()).hexdigest()[:12]
    return f"{prefix}{digest}"


def user(name: str, *, groups: list[str] | None = None, inline: list[dict] | None = None,
         attached: list[str] | None = None) -> dict:
    return {
        "UserName": name,
        "UserId": _id("AIDA", name),
        "Arn": user_arn(name),
        "Path": "/",
        "CreateDate": "2024-03-01T09:00:00+00:00",
        "GroupList": groups or [],
        "UserPolicyList": [
            {"PolicyName": n, "PolicyDocument": d} for n, d in (inline or [])
        ],
        "AttachedManagedPolicies": [
            {"PolicyName": n, "PolicyArn": attachment_arn(n)} for n in (attached or [])
        ],
    }


def group(name: str, *, inline: list[dict] | None = None,
          attached: list[str] | None = None) -> dict:
    return {
        "GroupName": name,
        "GroupId": _id("AGPA", name),
        "Arn": group_arn(name),
        "Path": "/",
        "CreateDate": "2024-03-01T09:00:00+00:00",
        "GroupPolicyList": [
            {"PolicyName": n, "PolicyDocument": d} for n, d in (inline or [])
        ],
        "AttachedManagedPolicies": [
            {"PolicyName": n, "PolicyArn": attachment_arn(n)} for n in (attached or [])
        ],
    }


def role(name: str, *, trust: dict, inline: list[dict] | None = None,
         attached: list[str] | None = None) -> dict:
    return {
        "RoleName": name,
        "RoleId": _id("AROA", name),
        "Arn": role_arn(name),
        "Path": "/",
        "CreateDate": "2024-03-01T09:00:00+00:00",
        "AssumeRolePolicyDocument": trust,
        "RolePolicyList": [
            {"PolicyName": n, "PolicyDocument": d} for n, d in (inline or [])
        ],
        "AttachedManagedPolicies": [
            {"PolicyName": n, "PolicyArn": attachment_arn(n)} for n in (attached or [])
        ],
    }


def managed(name: str, *statements: dict, arn: str | None = None) -> dict:
    return {
        "PolicyName": name,
        "PolicyId": _id("ANPA", name),
        "Arn": arn or policy_arn(name),
        "Path": "/",
        "DefaultVersionId": "v1",
        "AttachmentCount": 1,
        "IsAttachable": True,
        "CreateDate": "2024-03-01T09:00:00+00:00",
        "PolicyVersionList": [
            {
                "VersionId": "v1",
                "IsDefaultVersion": True,
                "Document": doc(*statements),
                "CreateDate": "2024-03-01T09:00:00+00:00",
            }
        ],
    }


def build() -> dict:
    alice_admin_role_trust = doc(
        allow("sts:AssumeRole", "*", Principal={"AWS": user_arn("alice")})
    )

    return {
        "UserDetailList": [
            # DevOps engineer: can rewrite policies and assume the admin role.
            user(
                "alice",
                groups=["Developers"],
                inline=[
                    (
                        "Escalate",
                        doc(
                            allow(
                                [
                                    "iam:CreatePolicyVersion",
                                    "iam:SetDefaultPolicyVersion",
                                    "iam:AttachRolePolicy",
                                    "iam:AttachUserPolicy",
                                    "iam:AttachGroupPolicy",
                                    "iam:PutRolePolicy",
                                    "iam:PutGroupPolicy",
                                    "iam:UpdateAssumeRolePolicy",
                                ],
                                "*",
                            )
                        ),
                    ),
                    (
                        "AssumeAdmin",
                        doc(allow("sts:AssumeRole", role_arn("AdminRole"))),
                    ),
                ],
            ),
            # Standing administrator.
            user("bob", attached=["AdministratorAccess"]),
            # Automation owner: passes roles to Lambda and CloudFormation.
            user(
                "carol",
                inline=[
                    (
                        "PassAndRun",
                        doc(
                            allow(
                                "iam:PassRole",
                                [role_arn("LambdaExecRole"), role_arn("CFNRole")],
                            ),
                            allow(["lambda:CreateFunction", "lambda:InvokeFunction"], "*"),
                            allow("cloudformation:CreateStack", "*"),
                            allow("ec2:RunInstances", "*"),
                        ),
                    )
                ],
            ),
            # Onboarding service user: can mint credentials for anyone.
            user(
                "dave",
                inline=[
                    (
                        "Onboarding",
                        doc(
                            allow("iam:CreateAccessKey", "*"),
                            allow("iam:CreateLoginProfile", "*"),
                            allow("iam:AddUserToGroup", "*"),
                        ),
                    )
                ],
            ),
            # Contractor: powerful permission but only with recent MFA.
            user(
                "erin",
                inline=[
                    (
                        "MfaOnlyAdmin",
                        doc(
                            allow(
                                "iam:PutUserPolicy",
                                "*",
                                Condition={
                                    "Bool": {"aws:MultiFactorAuthPresent": "true"}
                                },
                            )
                        ),
                    )
                ],
            ),
            # Batch operator: can hand any role to any service, but holds no
            # compute permissions itself (so only the wildcard rule fires).
            user(
                "frank",
                inline=[
                    (
                        "PassAnything",
                        doc(allow("iam:PassRole", "*")),
                    )
                ],
            ),
        ],
        "GroupDetailList": [
            group(
                "Developers",
                attached=["DeveloperAccess"],
            ),
            group("Admins", attached=["AdministratorAccess"]),
            group(
                "Auditors",
                attached=["AuditorBroadAccess"],
            ),
            group("SecurityTeam", attached=["IamFullAccessLocal"]),
        ],
        "RoleDetailList": [
            role(
                "AdminRole",
                trust=alice_admin_role_trust,
                attached=["AdministratorAccess"],
            ),
            role(
                "LambdaExecRole",
                trust=doc(allow("sts:AssumeRole", "*", Principal={"AWS": "*"})),
                inline=[("Logs", doc(allow("logs:PutLogEvents", "*")))],
            ),
            role(
                "CFNRole",
                trust=doc(
                    allow("sts:AssumeRole", "*", Principal={"AWS": user_arn("carol")})
                ),
                attached=["DeveloperAccess"],
            ),
            role(
                "LegacyCrossAccount",
                trust=doc(
                    allow(
                        "sts:AssumeRole",
                        "*",
                        Principal={"AWS": "arn:aws:iam::999999999999:root"},
                    )
                ),
                attached=["DeveloperAccess"],
            ),
            role(
                "ReportingRole",
                trust=doc(
                    allow(
                        "sts:AssumeRole",
                        "*",
                        Principal={"AWS": f"arn:aws:iam::{ACCOUNT}:root"},
                    )
                ),
                attached=["DeveloperAccess"],
            ),
        ],
        "Policies": [
            managed(
                "AdministratorAccess",
                allow("*", "*"),
                arn="arn:aws:iam::aws:policy/AdministratorAccess",
            ),
            managed(
                "DeveloperAccess",
                allow(["ec2:Describe*", "s3:Get*", "lambda:InvokeFunction"], "*"),
            ),
            managed(
                "AuditorBroadAccess",
                allow(
                    "*",
                    "*",
                    NotAction=[
                        "iam:*",
                        "organizations:*",
                        "account:*",
                        "sts:AssumeRole",
                    ],
                ),
            ),
            managed(
                "IamFullAccessLocal",
                allow("iam:*", "*"),
            ),
        ],
    }


def main() -> None:
    OUT.write_text(json.dumps(build(), indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {OUT}")


if __name__ == "__main__":
    main()
