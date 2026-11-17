"""Unit tests for ChaosProxy fault modes and TraceRecorder/TraceReplayer."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from mcp_guard.models import ToolDefinition
from mcp_guard.recorder.trace_manager import TraceRecorder, TraceReplayer, redact_secrets
from mcp_guard.transport.chaos_proxy import (
    ChaosFaultType,
    ChaosPolicy,
    ChaosProxy,
    run_chaos_suite,
)
from mcp_guard.transport.jsonrpc import is_valid_jsonrpc_response, make_response


def _mock_upstream(tool_name: str, args: dict) -> dict:
    return make_response(
        1,
        {"content": [{"type": "text", "text": f"ok:{tool_name}"}], "isError": False},
    )


def test_chaos_suite_exercises_all_six_fault_modes() -> None:
    results = run_chaos_suite(_mock_upstream, "get_weather", {"city": "Tokyo"}, seed=123)
    assert len(results) == len(list(ChaosFaultType))

    by_fault = {r["fault_type"]: r for r in results}
    assert by_fault["timeout"]["raised_exception"] is not None
    assert by_fault["rate_limit_429"]["response"] if "response" in by_fault["rate_limit_429"] else True
    assert by_fault["rate_limit_429"]["record"]["response"]["error"]["code"] == -32029
    assert by_fault["internal_error_500"]["record"]["response"]["error"]["code"] == -32603
    assert by_fault["malformed_json"]["valid_jsonrpc_envelope"] is False
    assert "unexpected_nested_v2_payload" in by_fault["schema_drift"]["record"]["response"]["result"]
    assert by_fault["empty_result"]["record"]["response"]["result"]["content"] == []


def test_chaos_proxy_selective_probability_with_seed_is_deterministic() -> None:
    p1 = ChaosProxy(
        _mock_upstream,
        ChaosPolicy(fault_type=ChaosFaultType.INTERNAL_ERROR_500, probability=0.5, seed=99),
    )
    p2 = ChaosProxy(
        _mock_upstream,
        ChaosPolicy(fault_type=ChaosFaultType.INTERNAL_ERROR_500, probability=0.5, seed=99),
    )
    seq1 = ["error" in p1.call_tool("demo", {}) for _ in range(10)]
    seq2 = ["error" in p2.call_tool("demo", {}) for _ in range(10)]
    assert seq1 == seq2
    assert any(seq1) and not all(seq1)


def test_secret_redaction_and_trace_replay_contract_diff(tmp_path: Path) -> None:
    # Construct synthetic test strings dynamically to verify secret redaction
    fake_gh_token = "ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"
    fake_sk_token = "sk-" + "9876543210abcdefghijklmnopqrstuv"
    sanitized = redact_secrets(
        {
            "authorization": f"Bearer {fake_gh_token}",
            "nested": {"api_key": fake_sk_token, "safe": "hello"},
        }
    )
    assert fake_gh_token not in json.dumps(sanitized)
    assert fake_sk_token not in json.dumps(sanitized)
    assert sanitized["nested"]["safe"] == "hello"

    recorder = TraceRecorder(target="demo-server")
    recorder.record("client->server", "tools/list", 1, {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    recorder.record(
        "server->client",
        "tools/list",
        1,
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "tools": [
                    {
                        "name": "search_docs",
                        "description": "Search docs.",
                        "inputSchema": {
                            "type": "object",
                            "properties": {"query": {"type": "string"}},
                            "required": ["query"],
                        },
                    }
                ]
            },
        },
    )
    recorder.record(
        "client->server",
        "tools/call",
        2,
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "search_docs", "arguments": {"query": fake_gh_token}}},
    )
    recorder.record(
        "server->client",
        "tools/call",
        2,
        make_response(2, {"content": [{"type": "text", "text": "done"}]}),
    )

    trace_file = tmp_path / "session.mcp-trace.json"
    recorder.save(trace_file)
    raw_saved = trace_file.read_text(encoding="utf-8")
    assert fake_gh_token not in raw_saved

    replayer = TraceReplayer.load(trace_file)
    assert len(replayer.extract_call_pairs()) == 1

    # Identical contract -> compatible
    same_tools = replayer.extract_recorded_tools()
    assert replayer.compare_with_tools(same_tools).compatible is True

    # Breaking change: type changed & new required param added
    drifted_tools = [
        ToolDefinition.from_dict(
            {
                "name": "search_docs",
                "description": "Search docs.",
                "inputSchema": {
                    "type": "object",
                    "properties": {"query": {"type": "integer"}, "namespace": {"type": "string"}},
                    "required": ["query", "namespace"],
                },
            }
        )
    ]
    diff = replayer.compare_with_tools(drifted_tools)
    assert diff.compatible is False
    assert len(diff.schema_mismatches) == 2
