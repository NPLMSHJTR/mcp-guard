"""Command-line interface for MCP-Guard & Studio."""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path
from typing import Any, Sequence

from mcp_guard import __version__
from mcp_guard.analyzers.fuzz_engine import FuzzEngine
from mcp_guard.analyzers.poisoning_scanner import PoisoningScanner
from mcp_guard.analyzers.schema_validator import SchemaValidator
from mcp_guard.models import AuditReport, RuleCategory, Severity, ToolDefinition
from mcp_guard.recorder.trace_manager import TraceRecorder, TraceReplayer
from mcp_guard.reporters.console_reporter import render_console_report
from mcp_guard.reporters.html_reporter import render_html_report
from mcp_guard.reporters.markdown_reporter import render_markdown_report
from mcp_guard.reporters.sarif_reporter import build_sarif_dict, render_sarif_report
from mcp_guard.rules_catalog import list_rules
from mcp_guard.studio.app import run_studio
from mcp_guard.transport.chaos_proxy import ChaosFaultType, ChaosPolicy, ChaosProxy, run_chaos_suite
from mcp_guard.transport.stdio_client import StdioMCPClient


def load_tools_from_file(path: str | Path) -> list[ToolDefinition]:
    """Load MCP ToolDefinitions from a JSON or JSONL file."""
    file_path = Path(path)
    raw_text = file_path.read_text(encoding="utf-8")

    if file_path.suffix.lower() == ".jsonl":
        tools: list[ToolDefinition] = []
        for line in raw_text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            item = json.loads(stripped)
            if isinstance(item, dict) and "tool" in item and isinstance(item["tool"], dict):
                tools.append(ToolDefinition.from_dict(item["tool"]))
            elif isinstance(item, dict) and "tools" in item and isinstance(item["tools"], list):
                tools.extend(ToolDefinition.from_dict(t) for t in item["tools"])
            elif isinstance(item, dict):
                tools.append(ToolDefinition.from_dict(item))
        return tools

    parsed = json.loads(raw_text)
    if isinstance(parsed, dict):
        if "tools" in parsed and isinstance(parsed["tools"], list):
            return [ToolDefinition.from_dict(t) for t in parsed["tools"]]
        if "tool" in parsed and isinstance(parsed["tool"], dict):
            return [ToolDefinition.from_dict(parsed["tool"])]
        return [ToolDefinition.from_dict(parsed)]
    if isinstance(parsed, list):
        return [ToolDefinition.from_dict(t) for t in parsed]
    raise ValueError(f"Unsupported JSON tool manifest structure in {file_path}")


def run_static_audit(tools: list[ToolDefinition], target: str) -> AuditReport:
    """Execute PoisoningScanner and SchemaValidator across `tools`."""
    start = time.perf_counter()
    sec_findings = PoisoningScanner().scan_tools(tools)
    schema_findings = SchemaValidator().scan_tools(tools)
    elapsed_ms = (time.perf_counter() - start) * 1000.0
    return AuditReport(
        target=target,
        tools_scanned=len(tools),
        tool_names=[t.name for t in tools],
        findings=sec_findings + schema_findings,
        duration_ms=elapsed_ms,
    )


def format_report(report: AuditReport, fmt: str, color: bool = True) -> str:
    fmt_lower = fmt.strip().lower()
    if fmt_lower == "console":
        return render_console_report(report, color=color)
    if fmt_lower == "json":
        return json.dumps(report.to_dict(), indent=2, ensure_ascii=False)
    if fmt_lower == "markdown":
        return render_markdown_report(report)
    if fmt_lower == "sarif":
        return render_sarif_report(report)
    if fmt_lower == "html":
        return render_html_report(report)
    raise ValueError(f"Unsupported report format: {fmt}")


def execute_scan_for_action(
    cmd: str | None = None,
    tools_file: str | None = None,
    report_format: str = "markdown",
    output_file: str | None = None,
    fail_on: str = "high",
    run_fuzz: bool = False,
    timeout: float = 5.0,
) -> dict[str, Any]:
    """Programmatic entrypoint used by GitHub Action (`action.yml`) and integrations."""
    if not cmd and not tools_file:
        raise ValueError("Either 'cmd' or 'tools_file' must be provided.")

    start = time.perf_counter()
    fuzz_results = []
    if cmd:
        with StdioMCPClient(cmd, timeout=timeout) as client:
            tools = client.list_tools()
            if run_fuzz:
                fuzz_results = FuzzEngine().fuzz_tools(tools, client.call_tool)
        target = cmd
    else:
        assert tools_file is not None
        tools = load_tools_from_file(tools_file)
        target = tools_file

    report = run_static_audit(tools, target=target)
    report.fuzz_results = fuzz_results
    report.duration_ms = (time.perf_counter() - start) * 1000.0

    rendered = format_report(report, report_format, color=False)
    if output_file:
        out_path = Path(output_file)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered + "\n", encoding="utf-8")

    fail_threshold: Severity | None = None if fail_on.lower() == "none" else Severity.parse(fail_on)
    passed = True if fail_threshold is None else report.passes(fail_on=fail_threshold)
    return {
        "findings_count": len(report.findings),
        "critical_count": report.severity_counts["CRITICAL"],
        "passed": passed,
        "report_path": output_file or "",
        "markdown_summary": render_markdown_report(report),
        "sarif": build_sarif_dict(report),
    }


def _emit_output(text: str, output_path: str | None) -> None:
    if output_path:
        p = Path(output_path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text + "\n", encoding="utf-8")
    else:
        print(text)


def _handle_scan(args: argparse.Namespace) -> int:
    if not args.cmd and not args.tools_file:
        print("Error: specify either --cmd or --tools-file.", file=sys.stderr)
        return 2

    start = time.perf_counter()
    recorder = TraceRecorder(target=args.cmd or args.tools_file) if args.save_trace else None
    fuzz_results = []

    if args.cmd:
        with StdioMCPClient(args.cmd, timeout=args.timeout, recorder=recorder) as client:
            tools = client.list_tools()
            if args.fuzz:
                fuzz_results = FuzzEngine().fuzz_tools(tools, client.call_tool)
        target = args.cmd
    else:
        tools = load_tools_from_file(args.tools_file)
        target = args.tools_file

    report = run_static_audit(tools, target=target)
    report.fuzz_results = fuzz_results
    report.duration_ms = (time.perf_counter() - start) * 1000.0

    if recorder and args.save_trace:
        recorder.save(args.save_trace)

    use_color = (not args.no_color) and sys.stdout.isatty()
    rendered = format_report(report, args.format, color=use_color)
    _emit_output(rendered, args.output)

    fail_threshold: Severity | None = (
        None if args.fail_on.lower() == "none" else Severity.parse(args.fail_on)
    )
    if fail_threshold is None:
        return 0
    return 0 if report.passes(fail_on=fail_threshold) else 1


def _handle_fuzz(args: argparse.Namespace) -> int:
    recorder = TraceRecorder(target=args.cmd) if args.save_trace else None
    start = time.perf_counter()
    with StdioMCPClient(args.cmd, timeout=args.timeout, recorder=recorder) as client:
        tools = client.list_tools()
        fuzz_results = FuzzEngine().fuzz_tools(
            tools, client.call_tool, max_cases_per_tool=args.max_cases
        )

    report = AuditReport(
        target=args.cmd,
        tools_scanned=len(tools),
        tool_names=[t.name for t in tools],
        fuzz_results=fuzz_results,
        duration_ms=(time.perf_counter() - start) * 1000.0,
    )
    if recorder and args.save_trace:
        recorder.save(args.save_trace)

    use_color = (not args.no_color) and sys.stdout.isatty()
    rendered = format_report(report, args.format, color=use_color)
    _emit_output(rendered, args.output)

    has_failures = any(r.outcome.is_failure for r in fuzz_results)
    if args.fail_on_crash and has_failures:
        return 1
    return 0


def _handle_chaos(args: argparse.Namespace) -> int:
    try:
        sample_args = json.loads(args.args) if args.args else {}
        if not isinstance(sample_args, dict):
            raise ValueError("--args must decode to a JSON object.")
    except (json.JSONDecodeError, ValueError) as exc:
        print(f"Error parsing --args JSON: {exc}", file=sys.stderr)
        return 2
    with StdioMCPClient(args.cmd, timeout=args.timeout) as client:
        if not args.tool:
            tools = client.list_tools()
            if not tools:
                print("Error: server exposed zero tools.", file=sys.stderr)
                return 2
            target_tool = tools[0].name
        else:
            target_tool = args.tool

        if args.all_faults:
            output_payload: Any = {
                "tool": target_tool,
                "suite_results": run_chaos_suite(
                    client.call_tool, target_tool, sample_args=sample_args, seed=args.seed
                ),
            }
        else:
            proxy = ChaosProxy(
                upstream_call=client.call_tool,
                policy=ChaosPolicy(
                    fault_type=ChaosFaultType(args.fault),
                    probability=1.0,
                    seed=args.seed,
                ),
            )
            try:
                resp = proxy.call_tool(target_tool, sample_args)
                output_payload = {
                    "tool": target_tool,
                    "fault": args.fault,
                    "raised_exception": None,
                    "response": resp,
                    "record": proxy.records[-1].to_dict(),
                }
            except TimeoutError as exc:
                output_payload = {
                    "tool": target_tool,
                    "fault": args.fault,
                    "raised_exception": str(exc),
                    "response": None,
                    "record": proxy.records[-1].to_dict(),
                }

    print(json.dumps(output_payload, indent=2, ensure_ascii=False))
    return 0


def _handle_replay(args: argparse.Namespace) -> int:
    replayer = TraceReplayer.load(args.trace)
    if args.cmd:
        with StdioMCPClient(args.cmd, timeout=args.timeout) as client:
            current_tools = client.list_tools()
    elif args.tools_file:
        current_tools = load_tools_from_file(args.tools_file)
    else:
        print("Error: provide --cmd or --tools-file to compare against trace.", file=sys.stderr)
        return 2

    diff = replayer.compare_with_tools(current_tools)
    if args.format == "json":
        print(json.dumps(diff.to_dict(), indent=2, ensure_ascii=False))
    else:
        status = "COMPATIBLE" if diff.compatible else "BREAKING CONTRACT DRIFT"
        print(f"Replay Contract Status: {status}")
        if diff.missing_tools:
            print(f"  Missing tools   : {diff.missing_tools}")
        if diff.added_tools:
            print(f"  Added tools     : {diff.added_tools}")
        for mismatch in diff.schema_mismatches:
            print(f"  Schema mismatch : {mismatch}")
    return 0 if diff.compatible else 1


def _handle_rules(args: argparse.Namespace) -> int:
    cat = RuleCategory(args.category) if args.category else None
    rules = list_rules(cat)
    if args.format == "json":
        print(json.dumps([r.to_dict() for r in rules], indent=2, ensure_ascii=False))
    else:
        for r in rules:
            print(f"{r.rule_id:<15} [{r.severity.value:<8}] ({r.category.value}) {r.title}")
    return 0


def _handle_studio(args: argparse.Namespace) -> int:
    run_studio(host=args.host, port=args.port, backend=args.backend)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcp-guard",
        description="Security scanner, JSON Schema contract validator, chaos proxy, and studio for MCP servers.",
    )
    parser.add_argument("--version", action="version", version=f"mcp-guard {__version__}")
    sub = parser.add_subparsers(dest="subcommand", required=True)

    # scan
    p_scan = sub.add_parser("scan", help="Scan an MCP server or JSON tool manifest for poisoning & schema flaws.")
    p_scan.add_argument("--cmd", help="Command to launch an MCP stdio server.")
    p_scan.add_argument("--tools-file", help="Path to JSON/JSONL file with MCP tool definitions.")
    p_scan.add_argument(
        "--format",
        default="console",
        choices=["console", "json", "markdown", "sarif", "html"],
        help="Output report format.",
    )
    p_scan.add_argument("--output", help="Write report output to a file path.")
    p_scan.add_argument(
        "--fail-on",
        default="high",
        choices=["critical", "high", "medium", "low", "none"],
        help="Minimum severity threshold to fail with non-zero exit code.",
    )
    p_scan.add_argument("--fuzz", action="store_true", help="Also run dynamic fuzzing against --cmd.")
    p_scan.add_argument("--save-trace", help="Optional path to record sanitized .mcp-trace.json.")
    p_scan.add_argument("--timeout", type=float, default=5.0, help="Per-request timeout in seconds.")
    p_scan.add_argument("--no-color", action="store_true", help="Disable ANSI terminal colors.")

    # fuzz
    p_fuzz = sub.add_parser("fuzz", help="Run boundary and malformed-input fuzzing against a live MCP stdio server.")
    p_fuzz.add_argument("--cmd", required=True, help="Command to launch an MCP stdio server.")
    p_fuzz.add_argument("--timeout", type=float, default=5.0, help="Per-call timeout in seconds.")
    p_fuzz.add_argument("--max-cases", type=int, default=None, help="Limit fuzz cases per tool.")
    p_fuzz.add_argument(
        "--format",
        default="console",
        choices=["console", "json", "markdown", "sarif", "html"],
    )
    p_fuzz.add_argument("--output", help="Write report output to a file path.")
    p_fuzz.add_argument("--save-trace", help="Save sanitized .mcp-trace.json.")
    p_fuzz.add_argument("--fail-on-crash", action="store_true", help="Exit 1 if any crash/leak/timeout occurs.")
    p_fuzz.add_argument("--no-color", action="store_true", help="Disable ANSI terminal colors.")

    # chaos
    p_chaos = sub.add_parser("chaos", help="Inject controlled chaos faults around live MCP tool calls.")
    p_chaos.add_argument("--cmd", required=True, help="Command to launch an MCP stdio server.")
    p_chaos.add_argument("--tool", help="Target tool name (defaults to first listed tool).")
    p_chaos.add_argument(
        "--fault",
        default=ChaosFaultType.RATE_LIMIT_429.value,
        choices=[f.value for f in ChaosFaultType],
    )
    p_chaos.add_argument("--all-faults", action="store_true", help="Run all 6 chaos modes sequentially.")
    p_chaos.add_argument("--args", default="{}", help="JSON arguments string.")
    p_chaos.add_argument("--seed", type=int, default=42, help="Deterministic PRNG seed.")
    p_chaos.add_argument("--timeout", type=float, default=5.0)

    # replay
    p_replay = sub.add_parser("replay", help="Compare a saved .mcp-trace.json contract against current tools.")
    p_replay.add_argument("--trace", required=True, help="Path to recorded .mcp-trace.json.")
    p_replay.add_argument("--tools-file", help="Current tools JSON/JSONL file.")
    p_replay.add_argument("--cmd", help="Live MCP server command.")
    p_replay.add_argument("--timeout", type=float, default=5.0)
    p_replay.add_argument("--format", default="console", choices=["console", "json"])

    # rules
    p_rules = sub.add_parser("rules", help="List all built-in security and schema detection rules.")
    p_rules.add_argument("--category", choices=["security", "schema"])
    p_rules.add_argument("--format", default="console", choices=["console", "json"])

    # studio
    p_studio = sub.add_parser("studio", help="Launch the interactive MCP-Guard Studio web UI.")
    p_studio.add_argument("--host", default="127.0.0.1")
    p_studio.add_argument("--port", type=int, default=8765)
    p_studio.add_argument("--backend", default="auto", choices=["auto", "builtin", "gradio"])

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass
    parser = build_parser()
    args = parser.parse_args(argv)
    dispatch = {
        "scan": _handle_scan,
        "fuzz": _handle_fuzz,
        "chaos": _handle_chaos,
        "replay": _handle_replay,
        "rules": _handle_rules,
        "studio": _handle_studio,
    }
    return dispatch[args.subcommand](args)


if __name__ == "__main__":
    raise SystemExit(main())
