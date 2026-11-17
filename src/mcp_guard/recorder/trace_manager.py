"""Trace recording with automatic secret redaction and deterministic offline contract replay."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from mcp_guard.models import ToolDefinition, TraceEvent

_SECRET_VALUE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"hf_[A-Za-z0-9]{20,}"),
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?i)Bearer\s+[A-Za-z0-9._\-]{12,}"),
)
_SENSITIVE_KEY_NAMES: frozenset[str] = frozenset(
    {"token", "api_key", "apikey", "secret", "password", "passwd", "authorization", "private_key"}
)


def redact_secrets(value: Any) -> Any:
    """Recursively mask common credential patterns and sensitive keys before persisting traces."""
    if isinstance(value, str):
        masked = value
        for pat in _SECRET_VALUE_PATTERNS:
            masked = pat.sub("[REDACTED]", masked)
        return masked
    if isinstance(value, list):
        return [redact_secrets(item) for item in value]
    if isinstance(value, dict):
        sanitized: dict[str, Any] = {}
        for k, v in value.items():
            if str(k).strip().lower() in _SENSITIVE_KEY_NAMES and isinstance(v, str) and v:
                sanitized[k] = "[REDACTED]"
            else:
                sanitized[k] = redact_secrets(v)
        return sanitized
    return value


@dataclass
class ReplayDiff:
    """Comparison summary between a baseline trace snapshot and current tools/responses."""

    compatible: bool
    missing_tools: list[str] = field(default_factory=list)
    added_tools: list[str] = field(default_factory=list)
    schema_mismatches: list[str] = field(default_factory=list)
    call_regressions: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "compatible": self.compatible,
            "missing_tools": self.missing_tools,
            "added_tools": self.added_tools,
            "schema_mismatches": self.schema_mismatches,
            "call_regressions": self.call_regressions,
        }


class TraceRecorder:
    """Captures JSON-RPC traffic and saves sanitized `.mcp-trace.json` snapshots."""

    def __init__(self, target: str) -> None:
        self.target = target
        self.created_at = datetime.now(timezone.utc).isoformat()
        self.events: list[TraceEvent] = []
        self._seq = 0

    def record(
        self,
        direction: str,
        method: str,
        request_id: int | str | None,
        payload: dict[str, Any],
        latency_ms: float = 0.0,
    ) -> TraceEvent:
        self._seq += 1
        safe_payload = redact_secrets(payload)
        event = TraceEvent(
            seq=self._seq,
            timestamp=datetime.now(timezone.utc).isoformat(),
            direction=direction,
            method=method,
            request_id=request_id,
            payload=safe_payload,
            latency_ms=latency_ms,
        )
        self.events.append(event)
        return event

    def to_dict(self) -> dict[str, Any]:
        events_data = [e.to_dict() for e in self.events]
        canonical = json.dumps(events_data, sort_keys=True, ensure_ascii=False)
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        return {
            "schema_version": "1.0",
            "target": self.target,
            "created_at": self.created_at,
            "event_count": len(events_data),
            "sha256": digest,
            "events": events_data,
        }

    def save(self, path: str | Path) -> Path:
        out_path = Path(path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(
            json.dumps(self.to_dict(), indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        return out_path


class TraceReplayer:
    """Loads recorded `.mcp-trace.json` traces and performs offline contract regression checks."""

    def __init__(self, trace_data: dict[str, Any]) -> None:
        self.trace_data = trace_data
        self.events = [TraceEvent.from_dict(e) for e in trace_data.get("events", [])]

    @classmethod
    def load(cls, path: str | Path) -> "TraceReplayer":
        raw = json.loads(Path(path).read_text(encoding="utf-8"))
        return cls(raw)

    def extract_recorded_tools(self) -> list[ToolDefinition]:
        """Extract the latest `tools/list` response snapshot from the trace."""
        for event in reversed(self.events):
            if event.direction == "server->client" and event.method == "tools/list":
                result = event.payload.get("result", {})
                tools = result.get("tools", [])
                if isinstance(tools, list):
                    return [ToolDefinition.from_dict(t) for t in tools if isinstance(t, dict)]
        return []

    def extract_call_pairs(self) -> list[tuple[str, dict[str, Any], dict[str, Any]]]:
        """Return `(tool_name, arguments, response_payload)` tuples recorded in the trace."""
        pending_reqs: dict[str | int, tuple[str, dict[str, Any]]] = {}
        pairs: list[tuple[str, dict[str, Any], dict[str, Any]]] = []
        for event in self.events:
            if (
                event.direction == "client->server"
                and event.method == "tools/call"
                and event.request_id is not None
            ):
                params = event.payload.get("params", {})
                tname = str(params.get("name", ""))
                args = params.get("arguments", {})
                pending_reqs[event.request_id] = (tname, args if isinstance(args, dict) else {})
            elif (
                event.direction == "server->client"
                and event.method == "tools/call"
                and event.request_id in pending_reqs
            ):
                tname, args = pending_reqs.pop(event.request_id)
                pairs.append((tname, args, event.payload))
        return pairs

    def compare_with_tools(self, current_tools: list[ToolDefinition]) -> ReplayDiff:
        """Compare recorded tool manifest contracts against `current_tools`."""
        baseline_tools = self.extract_recorded_tools()
        base_map = {t.name: t for t in baseline_tools}
        curr_map = {t.name: t for t in current_tools}

        missing = sorted(set(base_map) - set(curr_map))
        added = sorted(set(curr_map) - set(base_map))
        schema_mismatches: list[str] = []

        for name in sorted(set(base_map) & set(curr_map)):
            b_schema = base_map[name].input_schema or {}
            c_schema = curr_map[name].input_schema or {}
            b_req = set(b_schema.get("required", [])) if isinstance(b_schema.get("required"), list) else set()
            c_req = set(c_schema.get("required", [])) if isinstance(c_schema.get("required"), list) else set()
            if c_req - b_req:
                schema_mismatches.append(
                    f"Tool {name!r} added newly required field(s): {sorted(c_req - b_req)}"
                )

            b_props = b_schema.get("properties", {}) if isinstance(b_schema.get("properties"), dict) else {}
            c_props = c_schema.get("properties", {}) if isinstance(c_schema.get("properties"), dict) else {}
            removed_props = sorted(set(b_props) - set(c_props))
            if removed_props:
                schema_mismatches.append(
                    f"Tool {name!r} removed previously defined parameter(s): {removed_props}"
                )
            for pname in sorted(set(b_props) & set(c_props)):
                b_type = b_props[pname].get("type") if isinstance(b_props[pname], dict) else None
                c_type = c_props[pname].get("type") if isinstance(c_props[pname], dict) else None
                if b_type != c_type:
                    schema_mismatches.append(
                        f"Tool {name!r}.{pname} changed type from {b_type!r} to {c_type!r}"
                    )

        compatible = not missing and not schema_mismatches
        return ReplayDiff(
            compatible=compatible,
            missing_tools=missing,
            added_tools=added,
            schema_mismatches=schema_mismatches,
        )
