"""Tests for Console, SARIF 2.1.0, Markdown, HTML reporters, Studio logic, and CLI."""

from __future__ import annotations

import json
import sys
from pathlib import Path

from mcp_guard.cli import execute_scan_for_action, main
from mcp_guard.models import AuditReport, Finding, FuzzCaseResult, FuzzOutcome, RuleCategory, Severity
from mcp_guard.reporters.console_reporter import render_console_report
from mcp_guard.reporters.html_reporter import render_html_report
from mcp_guard.reporters.markdown_reporter import render_markdown_report
from mcp_guard.reporters.sarif_reporter import build_sarif_dict
from mcp_guard.studio.app import PRESET_PAYLOADS, audit_tools_json, simulate_chaos_payload

REPO_ROOT = Path(__file__).resolve().parent.parent


def _sample_report() -> AuditReport:
    return AuditReport(
        target="demo-server.py",
        tools_scanned=1,
        tool_names=["evil_tool"],
        findings=[
            Finding(
                rule_id="MCP-SEC-001",
                title="Direct Prompt Injection / System Override",
                category=RuleCategory.SECURITY,
                severity=Severity.CRITICAL,
                tool_name="evil_tool",
                location="description",
                message="Prompt injection marker detected.",
                evidence="<IMPORTANT> <script>alert(1)</script>",
                remediation="Remove directive.",
            )
        ],
        fuzz_results=[
            FuzzCaseResult(
                tool_name="evil_tool",
                case_name="x__zero",
                payload={"x": 0},
                outcome=FuzzOutcome.STACK_LEAK,
                latency_ms=4.2,
                detail="ZeroDivisionError leaked",
            )
        ],
    )


def test_all_report_formats_render_cleanly_and_escape_html() -> None:
    report = _sample_report()

    console = render_console_report(report, color=False)
    assert "MCP-SEC-001" in console
    assert "STACK_LEAK" in console

    md = render_markdown_report(report)
    assert "## MCP-Guard Audit Report (FAIL)" in md
    assert "`MCP-SEC-001`" in md

    sarif = build_sarif_dict(report)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert len(sarif["runs"][0]["results"]) == 2  # 1 static finding + 1 fuzz failure

    html_doc = render_html_report(report)
    assert "<!DOCTYPE html>" in html_doc
    assert "<script>alert(1)</script>" not in html_doc
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_doc


def test_studio_audit_and_chaos_helpers() -> None:
    benign = json.dumps(PRESET_PAYLOADS["Benign: Weather Lookup"])
    benign_res = audit_tools_json(benign)
    assert benign_res["passed"] is True
    assert benign_res["report"]["security_score"] == 100

    poisoned = json.dumps(PRESET_PAYLOADS["Poisoned: Prompt Injection & SSH Theft"])
    poisoned_res = audit_tools_json(poisoned)
    assert poisoned_res["passed"] is False
    assert poisoned_res["report"]["severity_counts"]["CRITICAL"] >= 2

    chaos_res = simulate_chaos_payload("get_weather_forecast", "rate_limit_429", '{"city":"Tokyo"}')
    assert chaos_res["response"]["error"]["code"] == -32029


def test_cli_subcommands_end_to_end(tmp_path: Path, capsys) -> None:
    assert main(["rules", "--category", "security", "--format", "json"]) == 0
    out_rules = json.loads(capsys.readouterr().out)
    assert len(out_rules) == 12

    hardened = REPO_ROOT / "examples" / "hardened_mcp_server.py"
    sarif_out = tmp_path / "out.sarif"
    rc = main(
        [
            "scan",
            "--cmd",
            f'"{sys.executable}" "{hardened}"',
            "--fuzz",
            "--format",
            "sarif",
            "--output",
            str(sarif_out),
            "--fail-on",
            "low",
        ]
    )
    assert rc == 0
    assert sarif_out.exists()
    sarif_data = json.loads(sarif_out.read_text(encoding="utf-8"))
    assert sarif_data["runs"][0]["results"] == []

    # Verify action wrapper
    action_res = execute_scan_for_action(
        cmd=f'"{sys.executable}" "{hardened}"',
        report_format="markdown",
        fail_on="low",
        run_fuzz=True,
    )
    assert action_res["passed"] is True
    assert action_res["findings_count"] == 0

    # Verify fail-on none diagnostic mode exits 0 even on vulnerable server with fuzz
    vulnerable = REPO_ROOT / "examples" / "vulnerable_mcp_server.py"
    rc_vuln = main(
        [
            "scan",
            "--cmd",
            f'"{sys.executable}" "{vulnerable}"',
            "--fuzz",
            "--fail-on",
            "none",
            "--no-color",
        ]
    )
    assert rc_vuln == 0
    _ = capsys.readouterr()

    # Verify invalid --args JSON returns clean exit code 2
    rc_bad_args = main(
        [
            "chaos",
            "--cmd",
            f'"{sys.executable}" "{hardened}"',
            "--args",
            "{invalid",
        ]
    )
    assert rc_bad_args == 2

