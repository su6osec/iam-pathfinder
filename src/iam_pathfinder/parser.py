"""Parser for ``aws iam get-account-authorization-details`` JSON output.

The export is a single JSON object with (among others) the keys
``UserDetailList``, ``GroupDetailList``, ``RoleDetailList`` and ``Policies``.
Policy documents inside the export may be raw JSON objects *or* URL-encoded
JSON strings depending on the CLI/API path that produced the file, so the
parser accepts both.

Nothing here touches the network; the only input is a local file.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from .model import (
    Account,
    Group,
    ManagedPolicy,
    PolicyDocument,
    Role,
    Statement,
    User,
    statement_from_dict,
)


class ParseError(Exception):
    """Raised when the input file is not a usable account export."""


_ARN_RE = re.compile(r"^arn:aws[a-z-]*:iam::(\d{12}):")


def _account_id_from_arn(arn: str) -> str | None:
    match = _ARN_RE.match(arn)
    return match.group(1) if match else None


def parse_policy_document(data: Any, *, context: str) -> list[Statement]:
    """Parse a policy document that may be a dict or a URL-encoded string.

    ``context`` is used in error messages so the user can find the broken
    document inside a large export.
    """
    if isinstance(data, str):
        # The IAM API historically returns policy documents URL-encoded.
        # Try the raw string first (in case it is already JSON), then decode.
        try:
            data = json.loads(data)
        except json.JSONDecodeError:
            try:
                data = json.loads(unquote(data))
            except json.JSONDecodeError as exc:
                raise ParseError(f"Policy document for {context} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict):
        raise ParseError(
            f"Policy document for {context} must be a JSON object, "
            f"got {type(data).__name__}"
        )
    statements = data.get("Statement", [])
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        raise ParseError(f"Policy document for {context} has a non-list Statement field")
    return [statement_from_dict(s) for s in statements if isinstance(s, dict)]


def _policy_doc_from_detail(detail: dict[str, Any], *, context: str) -> PolicyDocument:
    return PolicyDocument(
        name=str(detail.get("PolicyName", context)),
        statements=parse_policy_document(detail.get("PolicyDocument"), context=context),
    )


def _attached_refs(detail_list: list[dict[str, Any]]) -> list[tuple[str, str]]:
    refs: list[tuple[str, str]] = []
    for entry in detail_list or []:
        name = entry.get("PolicyName")
        arn = entry.get("PolicyArn")
        if name and arn:
            refs.append((str(name), str(arn)))
    return refs


def _group_names(user_detail: dict[str, Any]) -> tuple[str, ...]:
    """UserDetail.GroupList is an array of group *names* (strings).

    Be forgiving anyway: if a tool ever rewrote entries as objects, pick the
    name out of them instead of crashing.
    """
    names: list[str] = []
    for entry in user_detail.get("GroupList") or []:
        if isinstance(entry, str):
            names.append(entry)
        elif isinstance(entry, dict):
            name = entry.get("GroupName") or entry.get("Name")
            if name:
                names.append(str(name))
    return tuple(names)


def _parse_users(details: list[dict[str, Any]]) -> dict[str, User]:
    users: dict[str, User] = {}
    for detail in details or []:
        name = detail.get("UserName")
        if not name:
            continue
        arn = str(detail.get("Arn") or f"arn:aws:iam::000000000000:user/{name}")
        users[str(name)] = User(
            name=str(name),
            arn=arn,
            user_id=detail.get("UserId"),
            group_names=_group_names(detail),
            inline_policies=[
                _policy_doc_from_detail(p, context=f"inline policy of user {name}")
                for p in detail.get("UserPolicyList") or []
            ],
            attached_policy_refs=_attached_refs(detail.get("AttachedManagedPolicies") or []),
        )
    return users


def _parse_groups(details: list[dict[str, Any]]) -> dict[str, Group]:
    groups: dict[str, Group] = {}
    for detail in details or []:
        name = detail.get("GroupName")
        if not name:
            continue
        arn = str(detail.get("Arn") or f"arn:aws:iam::000000000000:group/{name}")
        groups[str(name)] = Group(
            name=str(name),
            arn=arn,
            group_id=detail.get("GroupId"),
            inline_policies=[
                _policy_doc_from_detail(p, context=f"inline policy of group {name}")
                for p in detail.get("GroupPolicyList") or []
            ],
            attached_policy_refs=_attached_refs(detail.get("AttachedManagedPolicies") or []),
        )
    return groups


def _parse_roles(details: list[dict[str, Any]]) -> dict[str, Role]:
    roles: dict[str, Role] = {}
    for detail in details or []:
        name = detail.get("RoleName")
        if not name:
            continue
        arn = str(detail.get("Arn") or f"arn:aws:iam::000000000000:role/{name}")
        trust = None
        trust_doc = detail.get("AssumeRolePolicyDocument")
        if trust_doc is not None:
            trust = PolicyDocument(
                name=f"trust policy of role {name}",
                statements=parse_policy_document(
                    trust_doc, context=f"trust policy of role {name}"
                ),
                arn=None,
            )
        roles[str(name)] = Role(
            name=str(name),
            arn=arn,
            role_id=detail.get("RoleId"),
            trust_policy=trust,
            inline_policies=[
                _policy_doc_from_detail(p, context=f"inline policy of role {name}")
                for p in detail.get("RolePolicyList") or []
            ],
            attached_policy_refs=_attached_refs(detail.get("AttachedManagedPolicies") or []),
        )
    return roles


def _parse_managed_policies(details: list[dict[str, Any]]) -> dict[str, ManagedPolicy]:
    policies: dict[str, ManagedPolicy] = {}
    for detail in details or []:
        arn = detail.get("Arn")
        name = detail.get("PolicyName")
        if not arn or not name:
            continue
        versions: dict[str, PolicyDocument] = {}
        default_id = detail.get("DefaultVersionId")
        for version in detail.get("PolicyVersionList") or []:
            version_id = version.get("VersionId")
            document = version.get("Document")
            if version_id is None or document is None:
                continue
            statements = parse_policy_document(
                document, context=f"policy {name} version {version_id}"
            )
            versions[str(version_id)] = PolicyDocument(
                name=str(name),
                statements=statements,
                arn=str(arn),
                version_id=str(version_id),
            )
        policies[str(arn)] = ManagedPolicy(
            name=str(name),
            arn=str(arn),
            default_version_id=str(default_id) if default_id else None,
            versions=versions,
        )
    return policies


def _derive_account_id(account: Account) -> str | None:
    for collection in (account.users, account.groups, account.roles, account.managed_policies):
        for entity in collection.values():
            found = _account_id_from_arn(entity.arn)
            if found:
                return found
    return None


@dataclass
class ParsedExport:
    """Result of parsing one export file."""

    account: Account
    # Managed policy ARNs referenced by attachments but absent from the export
    # (possible when the export was filtered).  Their permissions are NOT
    # analyzed; callers should surface this so results are not over-trusted.
    unresolved_policy_arns: list[str] = field(default_factory=list)


def parse_export(data: Any) -> ParsedExport:
    """Parse a decoded ``get-account-authorization-details`` response."""
    if not isinstance(data, dict):
        raise ParseError(
            "Input must be the JSON object returned by "
            f"'aws iam get-account-authorization-details', got {type(data).__name__}"
        )
    known_keys = {"UserDetailList", "GroupDetailList", "RoleDetailList", "Policies"}
    if data and not known_keys.intersection(data):  # {} is a valid empty export
        raise ParseError(
            "Input does not look like an IAM account export: none of "
            f"{sorted(known_keys)} found at the top level"
        )

    account = Account(
        users=_parse_users(data.get("UserDetailList") or []),
        groups=_parse_groups(data.get("GroupDetailList") or []),
        roles=_parse_roles(data.get("RoleDetailList") or []),
        managed_policies=_parse_managed_policies(data.get("Policies") or []),
    )
    account.account_id = _derive_account_id(account)

    # Every attachment must resolve to a document in the export, otherwise the
    # principal's effective permissions would be silently under-computed.
    unresolved: set[str] = set()
    for refs in (
        [u.attached_policy_refs for u in account.users.values()]
        + [g.attached_policy_refs for g in account.groups.values()]
        + [r.attached_policy_refs for r in account.roles.values()]
    ):
        for _, arn in refs:
            if arn not in account.managed_policies:
                unresolved.add(arn)

    return ParsedExport(account=account, unresolved_policy_arns=sorted(unresolved))


def load_export(path: str | Path) -> ParsedExport:
    """Read and parse an export file from disk."""
    file_path = Path(path)
    try:
        raw = file_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ParseError(f"Cannot read {file_path}: {exc}") from exc
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ParseError(f"{file_path} is not valid JSON: {exc}") from exc
    return parse_export(data)
