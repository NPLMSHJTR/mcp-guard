"""Zero-dependency standalone interactive HTML5 audit report generator."""

from __future__ import annotations

import html

from mcp_guard.models import AuditReport, Severity


def render_html_report(report: AuditReport) -> str:
    """Render a self-contained, filterable HTML5 report with SVG summary chart."""
    counts = report.severity_counts
    score = report.security_score
    score_color = "#10b981" if score >= 85 else "#f59e0b" if score >= 60 else "#ef4444"
    status_text = "PASS" if report.passes() else "ACTION REQUIRED"

    sorted_findings = sorted(
        report.findings,
        key=lambda f: (-f.severity.rank, f.tool_name, f.rule_id),
    )

    finding_rows: list[str] = []
    for f in sorted_findings:
        sev_cls = f.severity.value.lower()
        evidence_html = (
            f"<pre class='evidence'>{html.escape(f.evidence)}</pre>" if f.evidence else ""
        )
        finding_rows.append(
            f"""
            <tr class="finding-row" data-severity="{html.escape(sev_cls)}" data-category="{html.escape(f.category.value)}">
              <td><span class="badge badge-{html.escape(sev_cls)}">{html.escape(f.severity.value)}</span></td>
              <td><code>{html.escape(f.rule_id)}</code></td>
              <td><code>{html.escape(f.tool_name)}</code></td>
              <td><code>{html.escape(f.location)}</code></td>
              <td>
                <div class="msg-title">{html.escape(f.title)}</div>
                <div class="msg-body">{html.escape(f.message)}</div>
                {evidence_html}
                <div class="remediation"><strong>Fix:</strong> {html.escape(f.remediation)}</div>
              </td>
            </tr>
            """
        )

    findings_table_body = (
        "\n".join(finding_rows)
        if finding_rows
        else '<tr><td colspan="5" class="empty">No security or schema findings detected.</td></tr>'
    )

    fuzz_rows: list[str] = []
    for r in report.fuzz_results:
        badge_cls = "critical" if r.outcome.is_failure else "pass"
        fuzz_rows.append(
            f"""
            <tr>
              <td><span class="badge badge-{badge_cls}">{html.escape(r.outcome.value)}</span></td>
              <td><code>{html.escape(r.tool_name)}</code></td>
              <td><code>{html.escape(r.case_name)}</code></td>
              <td>{r.latency_ms:.1f} ms</td>
              <td>{html.escape(r.detail)}</td>
            </tr>
            """
        )
    fuzz_section = ""
    if report.fuzz_results:
        fuzz_section = f"""
        <section class="card">
          <h2>Dynamic Fuzz Cases ({len(report.fuzz_results)})</h2>
          <table>
            <thead>
              <tr><th>Outcome</th><th>Tool</th><th>Case</th><th>Latency</th><th>Detail</th></tr>
            </thead>
            <tbody>
              {''.join(fuzz_rows)}
            </tbody>
          </table>
        </section>
        """

    # Simple SVG severity bar chart
    max_count = max(1, max(counts.values()))
    bar_specs = [
        ("CRITICAL", counts["CRITICAL"], "#dc2626"),
        ("HIGH", counts["HIGH"], "#ea580c"),
        ("MEDIUM", counts["MEDIUM"], "#d97706"),
        ("LOW", counts["LOW"], "#0284c7"),
    ]
    svg_bars: list[str] = []
    for idx, (label, val, fill) in enumerate(bar_specs):
        y = 14 + idx * 28
        bar_w = int((val / max_count) * 180)
        svg_bars.append(
            f'<text x="0" y="{y + 14}" font-size="12" fill="#94a3b8" font-family="monospace">{label}</text>'
            f'<rect x="80" y="{y + 2}" width="{max(2, bar_w)}" height="16" rx="4" fill="{fill}" />'
            f'<text x="{88 + max(2, bar_w)}" y="{y + 14}" font-size="12" fill="#e2e8f0" font-family="monospace">{val}</text>'
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>MCP-Guard Audit Report - {html.escape(report.target)}</title>
  <style>
    :root {{
      --bg: #0f172a; --card: #1e293b; --border: #334155;
      --text: #f8fafc; --muted: #94a3b8;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0; padding: 24px; background: var(--bg); color: var(--text);
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    }}
    .container {{ max-width: 1180px; margin: 0 auto; }}
    .header {{ display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 16px; margin-bottom: 20px; }}
    .title h1 {{ margin: 0 0 6px 0; font-size: 24px; }}
    .meta {{ color: var(--muted); font-size: 13px; }}
    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 16px; margin-bottom: 20px; }}
    .card {{ background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 18px; margin-bottom: 20px; }}
    .kpi-label {{ color: var(--muted); font-size: 12px; text-transform: uppercase; letter-spacing: 0.05em; }}
    .kpi-val {{ font-size: 30px; font-weight: 700; margin-top: 6px; }}
    .controls {{ display: flex; gap: 10px; flex-wrap: wrap; margin-bottom: 14px; align-items: center; }}
    input, select {{
      background: #0f172a; color: var(--text); border: 1px solid var(--border);
      padding: 8px 12px; border-radius: 8px; font-size: 13px;
    }}
    table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
    th, td {{ text-align: left; padding: 10px 12px; border-bottom: 1px solid var(--border); vertical-align: top; }}
    th {{ color: var(--muted); font-weight: 600; }}
    code {{ background: #0f172a; padding: 2px 6px; border-radius: 4px; font-size: 12px; color: #38bdf8; }}
    .badge {{ display: inline-block; padding: 3px 8px; border-radius: 999px; font-size: 11px; font-weight: 700; }}
    .badge-critical {{ background: #7f1d1d; color: #fecaca; }}
    .badge-high {{ background: #7c2d12; color: #fed7aa; }}
    .badge-medium {{ background: #78350f; color: #fde68a; }}
    .badge-low {{ background: #0c4a6e; color: #bae6fd; }}
    .badge-info {{ background: #1e3a8a; color: #bfdbfe; }}
    .badge-pass {{ background: #064e3b; color: #a7f3d0; }}
    .msg-title {{ font-weight: 600; margin-bottom: 4px; }}
    .msg-body {{ color: #cbd5e1; margin-bottom: 6px; }}
    .evidence {{ background: #020617; border: 1px solid #1e293b; padding: 8px; border-radius: 6px; overflow-x: auto; font-size: 12px; color: #fda4af; white-space: pre-wrap; }}
    .remediation {{ color: #86efac; font-size: 12px; margin-top: 4px; }}
    .empty {{ text-align: center; color: #86efac; padding: 24px; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="title">
        <h1>MCP-Guard Security &amp; Contract Report</h1>
        <div class="meta">Target: <code>{html.escape(report.target)}</code> &middot; Status: <strong>{html.escape(status_text)}</strong></div>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <div class="kpi-label">Security Score</div>
        <div class="kpi-val" style="color: {score_color};">{score} / 100</div>
      </div>
      <div class="card">
        <div class="kpi-label">Tools Scanned</div>
        <div class="kpi-val">{report.tools_scanned}</div>
      </div>
      <div class="card">
        <div class="kpi-label">Total Findings</div>
        <div class="kpi-val">{len(report.findings)}</div>
      </div>
      <div class="card">
        <div class="kpi-label">Severity Breakdown</div>
        <svg width="310" height="128" viewBox="0 0 310 128" aria-label="Severity chart">
          {''.join(svg_bars)}
        </svg>
      </div>
    </div>

    <section class="card">
      <h2>Findings ({len(report.findings)})</h2>
      <div class="controls">
        <input id="searchBox" type="search" placeholder="Filter by rule, tool, or keyword..." oninput="filterRows()" />
        <select id="severityFilter" onchange="filterRows()">
          <option value="all">All Severities</option>
          <option value="critical">CRITICAL</option>
          <option value="high">HIGH</option>
          <option value="medium">MEDIUM</option>
          <option value="low">LOW</option>
        </select>
      </div>
      <table>
        <thead>
          <tr><th>Severity</th><th>Rule</th><th>Tool</th><th>Location</th><th>Details &amp; Remediation</th></tr>
        </thead>
        <tbody id="findingsBody">
          {findings_table_body}
        </tbody>
      </table>
    </section>

    {fuzz_section}
  </div>
  <script>
    function filterRows() {{
      const query = document.getElementById("searchBox").value.toLowerCase();
      const sev = document.getElementById("severityFilter").value;
      const rows = document.querySelectorAll(".finding-row");
      rows.forEach((row) => {{
        const matchesSev = sev === "all" || row.dataset.severity === sev;
        const matchesText = !query || row.innerText.toLowerCase().includes(query);
        row.style.display = (matchesSev && matchesText) ? "" : "none";
      }});
    }}
  </script>
</body>
</html>
"""
