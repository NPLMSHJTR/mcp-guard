"""GitHub-Flavored Markdown report generator for PR comments and CI Job Summaries."""

from __future__ import annotations

from mcp_guard.models import AuditReport


def _esc_md(text: str) -> str:
    return text.replace("|", "\\|").replace("\n", " ").replace("\r", "")


def render_markdown_report(report: AuditReport) -> str:
    """Render an AuditReport as clean GitHub-Flavored Markdown."""
    counts = report.severity_counts
    status_label = "PASS" if report.passes() else "FAIL"

    lines: list[str] = [
        f"## MCP-Guard Audit Report ({status_label})",
        "",
        f"- **Target**: `{report.target}`",
        f"- **Tools Scanned**: {report.tools_scanned}",
        f"- **Security Score**: **{report.security_score} / 100**",
        (
            f"- **Findings**: {len(report.findings)} "
            f"(CRITICAL: {counts['CRITICAL']}, HIGH: {counts['HIGH']}, "
            f"MEDIUM: {counts['MEDIUM']}, LOW: {counts['LOW']})"
        ),
        "",
    ]

    if not report.findings:
        lines.append("> No static security or schema violations were detected.")
    else:
        lines.append("### Findings")
        lines.append("")
        lines.append("| Severity | Rule ID | Tool | Location | Description |")
        lines.append("| :--- | :--- | :--- | :--- | :--- |")
        sorted_findings = sorted(
            report.findings,
            key=lambda f: (-f.severity.rank, f.tool_name, f.rule_id),
        )
        for f in sorted_findings:
            lines.append(
                f"| **{f.severity.value}** | `{f.rule_id}` | `{_esc_md(f.tool_name)}` | "
                f"`{_esc_md(f.location)}` | {_esc_md(f.message)} |"
            )

    if report.fuzz_results:
        failures = [r for r in report.fuzz_results if r.outcome.is_failure]
        lines.append("")
        lines.append(
            f"### Dynamic Fuzz Testing ({len(report.fuzz_results)} cases, {len(failures)} failures)"
        )
        lines.append("")
        if not failures:
            lines.append("> All boundary and malformed-input fuzz cases were handled safely.")
        else:
            lines.append("| Outcome | Tool | Case | Latency (ms) | Detail |")
            lines.append("| :--- | :--- | :--- | ---: | :--- |")
            for r in failures:
                lines.append(
                    f"| **{r.outcome.value}** | `{_esc_md(r.tool_name)}` | "
                    f"`{_esc_md(r.case_name)}` | {r.latency_ms:.1f} | {_esc_md(r.detail)} |"
                )

    lines.append("")
    return "\n".join(lines)
