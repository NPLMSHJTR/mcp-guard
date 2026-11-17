"""SARIF 2.1.0 report generator compatible with GitHub Code Scanning."""

from __future__ import annotations

import json
from typing import Any

from mcp_guard import __version__
from mcp_guard.models import AuditReport, Severity
from mcp_guard.rules_catalog import RULES_CATALOG

SARIF_SCHEMA_URL = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"


def _severity_to_sarif_level(severity: Severity) -> str:
    if severity in {Severity.CRITICAL, Severity.HIGH}:
        return "error"
    if severity == Severity.MEDIUM:
        return "warning"
    return "note"


def _severity_to_security_score(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "9.5",
        Severity.HIGH: "7.8",
        Severity.MEDIUM: "5.3",
        Severity.LOW: "2.5",
        Severity.INFO: "1.0",
    }[severity]


def build_sarif_dict(report: AuditReport) -> dict[str, Any]:
    """Convert an AuditReport into a SARIF 2.1.0 JSON-serializable dictionary."""
    referenced_rule_ids = sorted({f.rule_id for f in report.findings})
    driver_rules: list[dict[str, Any]] = []
    for rid in referenced_rule_ids:
        if rid in RULES_CATALOG:
            rule = RULES_CATALOG[rid]
            driver_rules.append(
                {
                    "id": rule.rule_id,
                    "name": rule.title,
                    "shortDescription": {"text": rule.title},
                    "fullDescription": {"text": rule.description},
                    "help": {"text": rule.remediation},
                    "defaultConfiguration": {"level": _severity_to_sarif_level(rule.severity)},
                    "properties": {
                        "category": rule.category.value,
                        "security-severity": _severity_to_security_score(rule.severity),
                        "tags": [t for t in ("security", "mcp", rule.category.value, rule.cwe) if t],
                    },
                }
            )
        else:
            driver_rules.append(
                {
                    "id": rid,
                    "name": rid,
                    "shortDescription": {"text": rid},
                }
            )

    results: list[dict[str, Any]] = []
    for f in report.findings:
        msg_text = f"[{f.tool_name} @ {f.location}] {f.message}"
        if f.evidence:
            msg_text += f" | Evidence: {f.evidence}"
        results.append(
            {
                "ruleId": f.rule_id,
                "level": _severity_to_sarif_level(f.severity),
                "message": {"text": msg_text},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": report.target},
                            "region": {"startLine": 1},
                        },
                        "logicalLocations": [
                            {
                                "name": f.tool_name,
                                "fullyQualifiedName": f"{f.tool_name}.{f.location}",
                                "kind": "function",
                            }
                        ],
                    }
                ],
                "properties": {
                    "severity": f.severity.value,
                    "toolName": f.tool_name,
                    "location": f.location,
                },
            }
        )

    for fuzz in report.fuzz_results:
        if not fuzz.outcome.is_failure:
            continue
        results.append(
            {
                "ruleId": f"MCP-FUZZ-{fuzz.outcome.value}",
                "level": "error",
                "message": {
                    "text": f"Fuzz case '{fuzz.case_name}' on tool '{fuzz.tool_name}' failed: {fuzz.detail}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": report.target},
                            "region": {"startLine": 1},
                        },
                        "logicalLocations": [
                            {
                                "name": fuzz.tool_name,
                                "fullyQualifiedName": f"{fuzz.tool_name}#{fuzz.case_name}",
                                "kind": "function",
                            }
                        ],
                    }
                ],
            }
        )

    return {
        "$schema": SARIF_SCHEMA_URL,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "MCP-Guard",
                        "version": __version__,
                        "informationUri": "https://github.com/mcp-guard/mcp-guard",
                        "rules": driver_rules,
                    }
                },
                "results": results,
            }
        ],
    }


def render_sarif_report(report: AuditReport) -> str:
    """Serialize an AuditReport to a formatted SARIF 2.1.0 JSON string."""
    return json.dumps(build_sarif_dict(report), indent=2, ensure_ascii=False)
