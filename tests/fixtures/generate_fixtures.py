"""Regenerates the true-positive/false-positive fixture pairs.

Run from the repository root::

    python tests/fixtures/generate_fixtures.py

Every rule registered in ``iam_pathfinder.rules`` must have a vulnerable
fixture (the rule MUST fire) and a safe fixture (NO rule may fire).  The
tests in ``tests/test_rules_*.py`` enforce that contract against these files,
so regenerate after adding a rule.

All data is synthetic: account 123456789012 only.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parents[1]))

from conftest import (  # noqa: E402
    export,
    group,
    local_policy_arn,
    managed_policy,
    role,
    stmt,
    user,
    user_arn,
)

FIXTURE_DIR = Path(__file__).parent
ACCOUNT = "123456789012"


def _read_only_policy() -> dict:
    """A harmless local managed policy used as a benign resource target."""
    return managed_policy("ReadOnlyTools", stmt(action="s3:GetObject", resource="*"))


def _unattached_policy() -> dict:
    """A local policy that exists but is attached to nobody."""
    return managed_policy("Unattached", stmt(action="s3:GetObject", resource="*"))


def _admin_policy() -> dict:
    return managed_policy("AdministratorAccess", stmt(action="*", resource="*"))


def _inline(name: str, *statements: dict) -> list[tuple[str, dict]]:
    from conftest import policy_document

    return [(name, policy_document(*statements))]


def _alice(inline: list[tuple[str, dict]] | None = None, attached: list[str] | None = None,
           groups: list[str] | None = None) -> dict:
    return user("alice", inline=inline, attached=attached, groups=groups)


# --- vulnerable fixtures ---------------------------------------------------

VULNERABLE: dict[str, dict] = {
    "IAM_CREATE_POLICY_VERSION": export(
        users=[
            _alice(
                inline=_inline(
                    "escalate",
                    stmt(action="iam:CreatePolicyVersion", resource="*"),
                ),
                attached=["TeamPolicy"],
            )
        ],
        policies=[
            managed_policy("TeamPolicy", stmt(action="s3:GetObject", resource="*")),
        ],
    ),
    "IAM_SET_DEFAULT_POLICY_VERSION": export(
        users=[
            _alice(
                inline=_inline(
                    "escalate",
                    stmt(action="iam:SetDefaultPolicyVersion", resource="*"),
                )
            )
        ],
    ),
    "IAM_ATTACH_USER_POLICY": export(
        users=[
            _alice(
                inline=_inline(
                    "escalate", stmt(action="iam:AttachUserPolicy", resource="*")
                )
            )
        ],
    ),
    "IAM_ATTACH_GROUP_POLICY": export(
        users=[
            _alice(
                inline=_inline(
                    "escalate", stmt(action="iam:AttachGroupPolicy", resource="*")
                ),
                groups=["devs"],
            )
        ],
        groups=[group("devs")],
    ),
    "IAM_ATTACH_ROLE_POLICY": export(
        users=[
            _alice(
                inline=_inline(
                    "escalate",
                    stmt(
                        action=["iam:AttachRolePolicy", "sts:AssumeRole"],
                        resource=f"arn:aws:iam::{ACCOUNT}:role/app",
                    ),
                )
            )
        ],
        roles=[
            role(
                "app",
                trust={
                    "Version": "2012-10-17",
                    "Statement": [
                        stmt("Allow", Principal={"AWS": user_arn("alice")}, Resource="*")
                    ],
                },
                attached=["ReadOnlyTools"],
            )
        ],
        policies=[_read_only_policy()],
    ),
    "IAM_PUT_USER_POLICY": export(
        users=[
            _alice(
                inline=_inline(
                    "escalate", stmt(action="iam:PutUserPolicy", resource="*")
                )
            )
        ],
    ),
    "IAM_PUT_GROUP_POLICY": export(
        users=[
            _alice(
                inline=_inline(
                    "escalate",
                    stmt(
                        action="iam:PutGroupPolicy",
                        resource=f"arn:aws:iam::{ACCOUNT}:group/devs",
                    ),
                ),
                groups=["devs"],
            )
        ],
        groups=[group("devs")],
    ),
    "IAM_PUT_ROLE_POLICY": export(
        users=[
            _alice(
                inline=_inline(
                    "escalate",
                    stmt(
                        action=["iam:PutRolePolicy", "sts:AssumeRole"],
                        resource=f"arn:aws:iam::{ACCOUNT}:role/app",
                    ),
                )
            )
        ],
        roles=[
            role(
                "app",
                trust={
                    "Version": "2012-10-17",
                    "Statement": [
                        stmt("Allow", Principal={"AWS": user_arn("alice")}, Resource="*")
                    ],
                },
            )
        ],
    ),
    "IAM_ADD_USER_TO_GROUP": export(
        users=[
            _alice(
                inline=_inline(
                    "escalate", stmt(action="iam:AddUserToGroup", resource="*")
                )
            )
        ],
        groups=[group("admins", attached=["AdministratorAccess"])],
        policies=[_admin_policy()],
    ),
    "IAM_CREATE_ACCESS_KEY": export(
        users=[
            _alice(
                inline=_inline(
                    "escalate",
                    stmt(
                        action="iam:CreateAccessKey",
                        resource=f"arn:aws:iam::{ACCOUNT}:user/bob",
                    ),
                )
            ),
            user("bob", attached=["AdministratorAccess"]),
        ],
        policies=[_admin_policy()],
    ),
    "IAM_LOGIN_PROFILE": export(
        users=[
            _alice(
                inline=_inline(
                    "escalate",
                    stmt(
                        action="iam:CreateLoginProfile",
                        resource=f"arn:aws:iam::{ACCOUNT}:user/bob",
                    ),
                )
            ),
            user("bob", attached=["AdministratorAccess"]),
        ],
        policies=[_admin_policy()],
    ),
    "IAM_UPDATE_ASSUME_ROLE_POLICY": export(
        users=[
            _alice(
                inline=_inline(
                    "escalate",
                    stmt(
                        action=["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
                        resource=f"arn:aws:iam::{ACCOUNT}:role/app",
                    ),
                )
            )
        ],
        roles=[
            role(
                "app",
                trust={
                    "Version": "2012-10-17",
                    "Statement": [
                        stmt("Allow", Principal={"AWS": user_arn("alice")}, Resource="*")
                    ],
                },
                attached=["AdministratorAccess"],
            )
        ],
        policies=[_admin_policy()],
    ),
}

# --- safe fixtures ---------------------------------------------------------
# Each safe fixture keeps the permission (or its neighbourhood) present but
# harmlessly scoped, and must produce ZERO findings of ANY rule.

SAFE: dict[str, dict] = {
    # Permission exists but targets a policy this principal does not own.
    "IAM_CREATE_POLICY_VERSION": export(
        users=[
            _alice(
                inline=_inline(
                    "limited",
                    stmt(
                        action="iam:CreatePolicyVersion",
                        resource=local_policy_arn("Unattached"),
                    ),
                )
            )
        ],
        policies=[_unattached_policy()],
    ),
    "IAM_SET_DEFAULT_POLICY_VERSION": export(
        users=[
            _alice(
                inline=_inline(
                    "limited",
                    stmt(
                        action="iam:SetDefaultPolicyVersion",
                        resource=local_policy_arn("Unattached"),
                    ),
                )
            )
        ],
        policies=[_unattached_policy()],
    ),
    # Scoped to a harmless, non-privileged policy ARN: attaching it escalates
    # nobody, so no finding is raised.
    "IAM_ATTACH_USER_POLICY": export(
        users=[
            _alice(
                inline=_inline(
                    "limited",
                    stmt(
                        action="iam:AttachUserPolicy",
                        resource=local_policy_arn("ReadOnlyTools"),
                    ),
                )
            )
        ],
        policies=[_read_only_policy()],
    ),
    "IAM_ATTACH_GROUP_POLICY": export(
        users=[
            _alice(
                inline=_inline(
                    "limited",
                    stmt(
                        action="iam:AttachGroupPolicy",
                        resource=local_policy_arn("ReadOnlyTools"),
                    ),
                ),
                groups=["devs"],
            )
        ],
        groups=[group("devs")],
        policies=[_read_only_policy()],
    ),
    "IAM_ATTACH_ROLE_POLICY": export(
        users=[
            _alice(
                inline=_inline(
                    "limited",
                    stmt(
                        action="iam:AttachRolePolicy",
                        resource=local_policy_arn("ReadOnlyTools"),
                    ),
                )
            )
        ],
        policies=[_read_only_policy()],
    ),
    # Scoped to a user ARN that does not exist: covers no real principal.
    "IAM_PUT_USER_POLICY": export(
        users=[
            _alice(
                inline=_inline(
                    "limited",
                    stmt(
                        action="iam:PutUserPolicy",
                        resource=f"arn:aws:iam::{ACCOUNT}:user/ghost",
                    ),
                )
            )
        ]
    ),
    "IAM_PUT_GROUP_POLICY": export(
        users=[
            _alice(
                inline=_inline(
                    "limited",
                    stmt(
                        action="iam:PutGroupPolicy",
                        resource=f"arn:aws:iam::{ACCOUNT}:group/ghost",
                    ),
                ),
                groups=["devs"],
            )
        ],
        groups=[group("devs")],
    ),
    "IAM_PUT_ROLE_POLICY": export(
        users=[
            _alice(
                inline=_inline(
                    "limited",
                    stmt(
                        action="iam:PutRolePolicy",
                        resource=f"arn:aws:iam::{ACCOUNT}:role/ghost",
                    ),
                )
            )
        ]
    ),
    # Scoped to a group that does not exist: covers no real group or user.
    "IAM_ADD_USER_TO_GROUP": export(
        users=[
            _alice(
                inline=_inline(
                    "limited",
                    stmt(
                        action="iam:AddUserToGroup",
                        resource=f"arn:aws:iam::{ACCOUNT}:group/ghost",
                    ),
                )
            )
        ]
    ),
    # Managing your OWN access key is legitimate self-service, not escalation.
    "IAM_CREATE_ACCESS_KEY": export(
        users=[
            _alice(
                inline=_inline(
                    "self-service",
                    stmt(action="iam:CreateAccessKey", resource=user_arn("alice")),
                )
            )
        ]
    ),
    "IAM_LOGIN_PROFILE": export(
        users=[
            _alice(
                inline=_inline(
                    "self-service",
                    stmt(action="iam:UpdateLoginProfile", resource=user_arn("alice")),
                )
            )
        ]
    ),
    # Trust editing without the matching sts:AssumeRole scope: the technique
    # needs both halves on the same role.
    "IAM_UPDATE_ASSUME_ROLE_POLICY": export(
        users=[
            _alice(
                inline=_inline(
                    "limited",
                    stmt(
                        action="iam:UpdateAssumeRolePolicy",
                        resource=f"arn:aws:iam::{ACCOUNT}:role/app",
                    ),
                    stmt(
                        action="sts:AssumeRole",
                        resource=f"arn:aws:iam::{ACCOUNT}:role/other",
                    ),
                )
            )
        ],
        roles=[
            role(
                "app",
                trust={
                    "Version": "2012-10-17",
                    "Statement": [
                        stmt("Allow", Principal={"AWS": user_arn("alice")}, Resource="*")
                    ],
                },
            ),
            role(
                "other",
                trust={
                    "Version": "2012-10-17",
                    "Statement": [
                        stmt("Allow", Principal={"AWS": user_arn("alice")}, Resource="*")
                    ],
                },
            ),
        ],
    ),
}


def main() -> None:
    missing = set(VULNERABLE) ^ set(SAFE)
    if missing:
        raise SystemExit(f"vulnerable/safe fixture mismatch: {sorted(missing)}")
    for category, fixtures in (("vulnerable", VULNERABLE), ("safe", SAFE)):
        out_dir = FIXTURE_DIR / category
        out_dir.mkdir(parents=True, exist_ok=True)
        for rule_id, data in sorted(fixtures.items()):
            path = out_dir / f"{rule_id}.json"
            path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            print(f"wrote {path.relative_to(FIXTURE_DIR.parent.parent)}")


if __name__ == "__main__":
    main()
