"""Core domain data structures for MCP-Guard."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Finding severity ordered from highest to lowest risk."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    @property
    def rank(self) -> int:
        return {
            Severity.CRITICAL: 4,
            Severity.HIGH: 3,
            Severity.MEDIUM: 2,
            Severity.LOW: 1,
            Severity.INFO: 0,
        }[self]

    @property
    def penalty(self) -> int:
        return {
            Severity.CRITICAL: 25,
            Severity.HIGH: 15,
            Severity.MEDIUM: 7,
            Severity.LOW: 2,
            Severity.INFO: 0,
        }[self]

    @classmethod
    def parse(cls, value: str) -> "Severity":
        normalized = value.strip().upper()
        for member in cls:
            if member.value == normalized:
                return member
        raise ValueError(f"Unsupported severity '{value}'. Expected one of: {[m.value for m in cls]}")


class RuleCategory(str, Enum):
    """Logical domain for an audit rule or runtime finding."""

    SECURITY = "security"
    SCHEMA = "schema"
    CONTRACT = "contract"
    CHAOS = "chaos"


class FuzzOutcome(str, Enum):
    """Execution outcome for a single fuzz payload against an MCP tool."""

    PASS = "PASS"
    GRACEFUL_ERROR = "GRACEFUL_ERROR"
    CRASH = "CRASH"
    TIMEOUT = "TIMEOUT"
    STACK_LEAK = "STACK_LEAK"
    PROTOCOL_VIOLATION = "PROTOCOL_VIOLATION"

    @property
    def is_failure(self) -> bool:
        return self in {
            FuzzOutcome.CRASH,
            FuzzOutcome.TIMEOUT,
            FuzzOutcome.STACK_LEAK,
            FuzzOutcome.PROTOCOL_VIOLATION,
        }


@dataclass(frozen=True)
class RuleDefinition:
    """Metadata describing a security or schema rule."""

    rule_id: str
    title: str
    category: RuleCategory
    severity: Severity
    description: str
    remediation: str
    cwe: str = ""
    owasp_llm: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "description": self.description,
            "remediation": self.remediation,
            "cwe": self.cwe,
            "owasp_llm": self.owasp_llm,
        }


@dataclass
class ToolDefinition:
    """Normalized representation of an MCP tool specification."""

    name: str
    description: str = ""
    input_schema: dict[str, Any] | None = None
    annotations: dict[str, Any] = field(default_factory=dict)
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "ToolDefinition":
        if not isinstance(data, dict):
            raise TypeError(f"Tool definition must be a dict, got {type(data).__name__}")
        name = str(data.get("name", ""))
        description = data.get("description")
        desc_str = "" if description is None else str(description)
        input_schema = data.get("inputSchema") if "inputSchema" in data else data.get("input_schema")
        annotations = data.get("annotations") if isinstance(data.get("annotations"), dict) else {}
        return cls(
            name=name,
            description=desc_str,
            input_schema=input_schema if isinstance(input_schema, dict) else None,
            annotations=dict(annotations),
            raw=dict(data),
        )

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "name": self.name,
            "description": self.description,
        }
        if self.input_schema is not None:
            out["inputSchema"] = self.input_schema
        if self.annotations:
            out["annotations"] = self.annotations
        return out


@dataclass
class Finding:
    """Individual rule violation or runtime issue discovered during auditing."""

    rule_id: str
    title: str
    category: RuleCategory
    severity: Severity
    tool_name: str
    location: str
    message: str
    evidence: str = ""
    remediation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "category": self.category.value,
            "severity": self.severity.value,
            "tool_name": self.tool_name,
            "location": self.location,
            "message": self.message,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


@dataclass
class FuzzCaseResult:
    """Outcome of invoking an MCP tool with a single boundary/malformed input case."""

    tool_name: str
    case_name: str
    payload: dict[str, Any]
    outcome: FuzzOutcome
    latency_ms: float
    detail: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool_name": self.tool_name,
            "case_name": self.case_name,
            "payload": self.payload,
            "outcome": self.outcome.value,
            "latency_ms": round(self.latency_ms, 2),
            "detail": self.detail,
        }


@dataclass
class TraceEvent:
    """Single JSON-RPC message captured on the MCP wire."""

    seq: int
    timestamp: str
    direction: str  # "client->server" or "server->client"
    method: str
    request_id: str | int | None
    payload: dict[str, Any]
    latency_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "seq": self.seq,
            "timestamp": self.timestamp,
            "direction": self.direction,
            "method": self.method,
            "request_id": self.request_id,
            "payload": self.payload,
            "latency_ms": round(self.latency_ms, 2),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "TraceEvent":
        return cls(
            seq=int(data["seq"]),
            timestamp=str(data["timestamp"]),
            direction=str(data["direction"]),
            method=str(data.get("method", "")),
            request_id=data.get("request_id"),
            payload=dict(data.get("payload", {})),
            latency_ms=float(data.get("latency_ms", 0.0)),
        )


@dataclass
class AuditReport:
    """Aggregated static + dynamic audit report for an MCP server or tool manifest."""

    target: str
    tools_scanned: int
    findings: list[Finding] = field(default_factory=list)
    fuzz_results: list[FuzzCaseResult] = field(default_factory=list)
    tool_names: list[str] = field(default_factory=list)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    duration_ms: float = 0.0

    @property
    def severity_counts(self) -> dict[str, int]:
        counts = {sev.value: 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity.value] += 1
        return counts

    @property
    def security_score(self) -> int:
        """Compute a 0-100 hygiene/security score where 100 indicates zero issues."""
        total_penalty = sum(f.severity.penalty for f in self.findings)
        for fuzz in self.fuzz_results:
            if fuzz.outcome == FuzzOutcome.CRASH:
                total_penalty += 25
            elif fuzz.outcome in {FuzzOutcome.STACK_LEAK, FuzzOutcome.PROTOCOL_VIOLATION}:
                total_penalty += 15
            elif fuzz.outcome == FuzzOutcome.TIMEOUT:
                total_penalty += 10
        return max(0, 100 - total_penalty)

    def passes(self, fail_on: Severity | None = Severity.HIGH) -> bool:
        """Return True if no finding meets or exceeds `fail_on` and no fuzz crash/leak occurred."""
        if fail_on is not None:
            for finding in self.findings:
                if finding.severity.rank >= fail_on.rank:
                    return False
        for fuzz in self.fuzz_results:
            if fuzz.outcome.is_failure:
                return False
        return True

    def to_dict(self) -> dict[str, Any]:
        fuzz_failures = sum(1 for r in self.fuzz_results if r.outcome.is_failure)
        return {
            "target": self.target,
            "timestamp": self.timestamp,
            "duration_ms": round(self.duration_ms, 2),
            "tools_scanned": self.tools_scanned,
            "tool_names": self.tool_names,
            "security_score": self.security_score,
            "severity_counts": self.severity_counts,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "fuzz_total": len(self.fuzz_results),
            "fuzz_failures": fuzz_failures,
            "fuzz_results": [r.to_dict() for r in self.fuzz_results],
        }
