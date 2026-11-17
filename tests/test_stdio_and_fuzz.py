"""End-to-end integration tests for StdioMCPClient and FuzzEngine against example servers."""

from __future__ import annotations

import shlex
import sys
from pathlib import Path

from mcp_guard.analyzers.fuzz_engine import FuzzEngine
from mcp_guard.cli import run_static_audit
from mcp_guard.models import FuzzOutcome, Severity
from mcp_guard.recorder.trace_manager import TraceRecorder
from mcp_guard.transport.stdio_client import StdioMCPClient

REPO_ROOT = Path(__file__).resolve().parent.parent
VULNERABLE_SERVER = REPO_ROOT / "examples" / "vulnerable_mcp_server.py"
HARDENED_SERVER = REPO_ROOT / "examples" / "hardened_mcp_server.py"


def _py_cmd(script: Path) -> list[str]:
    return [sys.executable, str(script)]


def test_vulnerable_server_detected_by_static_scan_and_live_fuzz() -> None:
    recorder = TraceRecorder(target=str(VULNERABLE_SERVER))
    with StdioMCPClient(_py_cmd(VULNERABLE_SERVER), timeout=5.0, recorder=recorder) as client:
        tools = client.list_tools()
        assert len(tools) == 4

        report = run_static_audit(tools, target=str(VULNERABLE_SERVER))
        assert not report.passes(fail_on=Severity.CRITICAL)
        rule_ids = {f.rule_id for f in report.findings}
        assert "MCP-SEC-001" in rule_ids
        assert "MCP-SEC-002" in rule_ids
        assert "MCP-SEC-003" in rule_ids
        assert "MCP-SEC-005" in rule_ids
        assert "MCP-SEC-006" in rule_ids

        fuzz_results = FuzzEngine().fuzz_tools(tools, client.call_tool)
        assert len(fuzz_results) > 0
        leaks = [r for r in fuzz_results if r.outcome == FuzzOutcome.STACK_LEAK]
        assert len(leaks) >= 1  # divide_numbers leaks ZeroDivisionError / TypeError traceback

    assert len(recorder.events) >= 4


def test_hardened_server_passes_all_static_and_fuzz_checks() -> None:
    with StdioMCPClient(_py_cmd(HARDENED_SERVER), timeout=5.0) as client:
        tools = client.list_tools()
        assert len(tools) == 4

        report = run_static_audit(tools, target=str(HARDENED_SERVER))
        assert report.findings == [], f"Unexpected findings on hardened server: {report.findings}"
        assert report.security_score == 100
        assert report.passes(fail_on=Severity.LOW)

        fuzz_results = FuzzEngine().fuzz_tools(tools, client.call_tool)
        assert len(fuzz_results) >= 20
        failures = [r for r in fuzz_results if r.outcome.is_failure]
        assert failures == [], f"Hardened server failed fuzz cases: {failures}"
        assert report.passes(fail_on=Severity.LOW)


def test_fuzz_engine_handles_crash_and_timeout_callables() -> None:
    from mcp_guard.models import ToolDefinition

    tool = ToolDefinition.from_dict(
        {
            "name": "flaky_tool",
            "description": "Test tool for crash/timeout handling.",
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
                "properties": {"x": {"type": "integer", "description": "Value."}},
                "required": ["x"],
            },
        }
    )

    def crashing_call(name: str, args: dict) -> dict:
        if args.get("x") == 0:
            raise EOFError("Simulated server segfault")
        raise TimeoutError("Simulated hang")

    results = FuzzEngine().fuzz_tool(tool, crashing_call)
    outcomes = {r.outcome for r in results}
    assert FuzzOutcome.CRASH in outcomes
    assert FuzzOutcome.TIMEOUT in outcomes
