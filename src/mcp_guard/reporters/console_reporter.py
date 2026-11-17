"""Human-readable ANSI/plain-text terminal diagnostic report generator."""

from __future__ import annotations

from mcp_guard.models import AuditReport, Severity

_ANSI_RESET = "\033[0m"
_ANSI_BOLD = "\033[1m"
_ANSI_DIM = "\033[2m"
_ANSI_COLORS = {
    Severity.CRITICAL: "\033[91m",  # Bright Red
    Severity.HIGH: "\033[31m",      # Red
    Severity.MEDIUM: "\033[33m",    # Yellow
    Severity.LOW: "\033[36m",       # Cyan
    Severity.INFO: "\033[34m",      # Blue
}


def render_console_report(report: AuditReport, color: bool = True) -> str:
    """Format an AuditReport into a clean terminal output string."""
    def paint(text: str, code: str) -> str:
        return f"{code}{text}{_ANSI_RESET}" if color else text

    lines: list[str] = []
    lines.append("=" * 72)
    lines.append(paint("  MCP-Guard Audit Report", _ANSI_BOLD))
    lines.append("=" * 72)
    lines.append(f"Target         : {report.target}")
    lines.append(f"Tools Scanned  : {report.tools_scanned}")
    lines.append(f"Security Score : {report.security_score} / 100")

    counts = report.severity_counts
    summary_parts = [f"{sev}: {counts[sev]}" for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")]
    lines.append(f"Findings       : {len(report.findings)} ({', '.join(summary_parts)})")

    if report.fuzz_results:
        failures = sum(1 for r in report.fuzz_results if r.outcome.is_failure)
        lines.append(
            f"Fuzz Cases     : {len(report.fuzz_results)} run, {failures} failure(s)"
        )
    lines.append("-" * 72)

    if not report.findings:
        lines.append(paint("[PASS] No static security or schema findings detected.", "\033[92m"))
    else:
        sorted_findings = sorted(
            report.findings,
            key=lambda f: (-f.severity.rank, f.tool_name, f.rule_id),
        )
        for idx, f in enumerate(sorted_findings, 1):
            sev_badge = paint(f"[{f.severity.value:<8}]", _ANSI_COLORS.get(f.severity, ""))
            lines.append(f"{idx:>2}. {sev_badge} {f.rule_id} | {f.title}")
            lines.append(f"    Tool       : {f.tool_name} ({f.location})")
            lines.append(f"    Detail     : {f.message}")
            if f.evidence:
                lines.append(f"    Evidence   : {paint(f.evidence, _ANSI_DIM)}")
            if f.remediation:
                lines.append(f"    Remediation: {f.remediation}")
            lines.append("")

    if report.fuzz_results:
        lines.append("-" * 72)
        lines.append(paint("  Dynamic Fuzz Summary", _ANSI_BOLD))
        lines.append("-" * 72)
        failing = [r for r in report.fuzz_results if r.outcome.is_failure]
        if not failing:
            lines.append(
                paint(
                    f"[PASS] All {len(report.fuzz_results)} fuzz case(s) handled gracefully.",
                    "\033[92m",
                )
            )
        else:
            for r in failing:
                badge = paint(f"[{r.outcome.value}]", "\033[91m")
                lines.append(f"  {badge} {r.tool_name} :: {r.case_name} ({r.latency_ms:.1f} ms)")
                lines.append(f"      {r.detail}")

    lines.append("=" * 72)
    return "\n".join(lines)
