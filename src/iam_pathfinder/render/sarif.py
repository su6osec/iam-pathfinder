"""SARIF 2.1.0 renderer - uploads results to GitHub code scanning etc."""

from __future__ import annotations

import hashlib
import json

from .. import REPOSITORY_URL
from ..rules import ALL_RULES
from ..rules.base import Finding, Severity
from .report import Report

SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/"
    "Schemata/sarif-schema-2.1.0.json"
)

_LEVELS = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def _rule_entry(rule) -> dict:
    entry = {
        "id": rule.id,
        "name": rule.id,
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.explanation},
        "help": {"text": f"{rule.explanation}\n\nRemediation: {rule.remediation}"},
        "properties": {
            "category": rule.category,
            "severity": rule.severity.label,
            "tags": ["aws", "iam", "privilege-escalation", rule.category],
        },
    }
    if rule.references:
        entry["helpUri"] = rule.references[0]
        entry["properties"]["references"] = list(rule.references)
    if rule.required_permissions:
        entry["properties"]["requiredPermissions"] = list(rule.required_permissions)
    return entry


def _result(finding: Finding) -> dict:
    fingerprint = hashlib.sha256(
        f"{finding.rule_id}|{finding.principal_arn}".encode()
    ).hexdigest()[:16]
    text = f"{finding.title} ({finding.principal_type} {finding.principal_name})"
    if finding.conditional:
        text += " [conditional: statement has a Condition]"
    return {
        "ruleId": finding.rule_id,
        "level": _LEVELS[finding.severity],
        "message": {"text": text},
        "locations": [
            {
                "logicalLocations": [
                    {
                        "name": finding.principal_name,
                        "kind": finding.principal_type,
                        "fullyQualifiedName": finding.principal_arn,
                    }
                ]
            }
        ],
        "partialFingerprints": {"primaryLocationLineHash": fingerprint},
        "properties": {
            "severity": finding.severity.label,
            "confidence": finding.confidence,
            "conditional": finding.conditional,
            "permissions": list(finding.permissions),
            "notes": list(finding.notes),
        },
    }


def payload(report: Report) -> dict:
    run = {
        "tool": {
            "driver": {
                "name": "iam-pathfinder",
                "version": report.tool_version,
                "informationUri": REPOSITORY_URL,
                "rules": [_rule_entry(rule) for rule in ALL_RULES],
            }
        },
        "results": [_result(finding) for finding in report.findings],
        "invocations": [
            {
                "executionSuccessful": True,
                "properties": {
                    "export": report.export_path,
                    "account_id": report.account_id,
                    "offline": True,
                    "min_severity": report.min_severity.label,
                    "escalation_paths": len(report.paths),
                },
            }
        ],
        "properties": {
            "escalationPaths": [report.path_dict(p) for p in report.paths],
            "summary": report.meta_dict()["summary"],
        },
    }
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [run],
    }


def render(report: Report) -> str:
    return json.dumps(payload(report), indent=2, default=str) + "\n"
