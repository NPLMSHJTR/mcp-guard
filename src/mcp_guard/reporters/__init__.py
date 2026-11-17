"""Report generators (Console, SARIF 2.1.0, Markdown, and standalone HTML) for MCP-Guard."""

from mcp_guard.reporters.console_reporter import render_console_report
from mcp_guard.reporters.html_reporter import render_html_report
from mcp_guard.reporters.markdown_reporter import render_markdown_report
from mcp_guard.reporters.sarif_reporter import build_sarif_dict, render_sarif_report

__all__ = [
    "build_sarif_dict",
    "render_console_report",
    "render_html_report",
    "render_markdown_report",
    "render_sarif_report",
]
