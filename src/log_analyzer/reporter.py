"""Report exporters for terminal summary, CSV, JSON, and standalone offline HTML."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any

from log_analyzer.models import AnalysisResult
from log_analyzer.security import safe_html, sanitize_csv_cell


def format_terminal_summary(
    result: AnalysisResult,
    report_paths: dict[str, Path] | None = None,
) -> str:
    """Format a comprehensive, human-readable terminal summary of the analysis."""
    lines: list[str] = []
    sep = "=" * 84
    subsep = "-" * 84

    lines.append(sep)
    lines.append("  PYTHON LOG ANALYZER & FAILURE CLASSIFIER — EXECUTIVE SUMMARY")
    lines.append(sep)
    lines.append(f"  Run ID              : {result.run_id}")
    lines.append(f"  Generated At (UTC)  : {result.generated_at.strftime('%Y-%m-%d %H:%M:%SZ')}")
    lines.append(
        f"  Files Scanned       : {result.total_files_scanned} "
        f"(Incremental Skipped: {result.total_files_skipped_incremental})"
    )
    lines.append(f"  Total Lines Read    : {result.total_lines_read:,}")
    lines.append(
        f"  Events Analyzed     : {result.total_events_analyzed:,} "
        f"(Parsed: {result.total_events_parsed:,} | Deduplicated: {result.duplicate_events_skipped:,} | Filtered: {result.filtered_events_skipped:,})"
    )
    lines.append(
        f"  Failure Events      : {result.total_error_events:,} Errors/Critical | "
        f"{result.total_warning_events:,} Warnings"
    )
    lines.append(f"  Unique Error Groups : {len(result.error_groups)}")
    lines.append(f"  Anomaly Spikes      : {len(result.anomaly_alerts)}")
    lines.append(
        f"  Parser Diagnostics  : {result.malformed_lines_count} malformed lines | "
        f"{result.missing_timestamp_count} missing/invalid timestamps"
    )
    lines.append(f"  Secrets Redacted    : {result.redactions_applied} sensitive value(s) masked")
    if result.time_range_start and result.time_range_end:
        lines.append(
            f"  Observed Time Range : {result.time_range_start.strftime('%Y-%m-%d %H:%M:%SZ')} -> "
            f"{result.time_range_end.strftime('%Y-%m-%d %H:%M:%SZ')}"
        )
    lines.append(f"  Situation Trend     : {result.trend_summary}")

    # Severity Breakdown
    lines.append("")
    lines.append(subsep)
    lines.append("  SEVERITY DISTRIBUTION")
    lines.append(subsep)
    tot_ev = max(result.total_events_analyzed, 1)
    for sev in ("CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "UNKNOWN"):
        cnt = result.severity_counts.get(sev, 0)
        if cnt > 0 or sev in ("CRITICAL", "ERROR", "WARNING", "INFO"):
            pct = (cnt / tot_ev) * 100.0
            lines.append(f"  {sev:<10} : {cnt:>8,}  ({pct:>5.1f}%)")

    # Failure Categories
    lines.append("")
    lines.append(subsep)
    lines.append("  FAILURE CATEGORIES (DETERMINISTIC RULE CLASSIFICATION)")
    lines.append(subsep)
    failure_cats = [
        (cat, cnt)
        for cat, cnt in sorted(result.category_counts.items(), key=lambda x: x[1], reverse=True)
        if cat != "Normal Operation" and cnt > 0
    ]
    if failure_cats:
        tot_cat = max(sum(c for _, c in failure_cats), 1)
        for cat, cnt in failure_cats:
            pct = (cnt / tot_cat) * 100.0
            lines.append(f"  {cat:<42} : {cnt:>7,}  ({pct:>5.1f}%)")
    else:
        lines.append("  No failure categories recorded.")

    # Affected Services
    lines.append("")
    lines.append(subsep)
    lines.append("  AFFECTED SERVICES & COMPONENTS")
    lines.append(subsep)
    for srv, tot_c in sorted(
        result.service_counts.items(),
        key=lambda kv: (result.service_error_counts.get(kv[0], 0), kv[1]),
        reverse=True,
    )[:10]:
        err_c = result.service_error_counts.get(srv, 0)
        err_rate = (err_c / max(tot_c, 1)) * 100.0
        lines.append(
            f"  {srv:<28} : {err_c:>6,} errors / {tot_c:>7,} events ({err_rate:>5.1f}% error rate)"
        )

    # Anomaly Alerts
    lines.append("")
    lines.append(subsep)
    lines.append(f"  DETECTED ANOMALY & THRESHOLD SPIKES ({len(result.anomaly_alerts)})")
    lines.append(subsep)
    if result.anomaly_alerts:
        for alert in result.anomaly_alerts:
            lines.append(
                f"  [{alert.alert_id}] {alert.severity_label} ({alert.alert_type.upper()}) @ "
                f"{alert.window_start.strftime('%Y-%m-%d %H:%M:%SZ')} ({alert.window_size})"
            )
            lines.append(
                f"      Count={alert.observed_count} | Baseline Median={alert.baseline_median:.1f} "
                f"(Mean={alert.baseline_mean:.1f}) | Ratio={alert.ratio_over_baseline:.1f}x | "
                f"Mod-Z={alert.modified_z_score:.2f}"
            )
            lines.append(f"      Reason: {alert.explanation}")
    else:
        note = result.anomaly_diagnostics.get("note", "No spikes exceeded thresholds.")
        lines.append(f"  No anomaly alerts triggered. ({note})")

    # Top Recurring Error Groups
    lines.append("")
    lines.append(subsep)
    lines.append(
        f"  TOP RECURRING FAILURE GROUPS (SHOWING TOP {min(len(result.error_groups), 10)})"
    )
    lines.append(subsep)
    if result.error_groups:
        for idx, grp in enumerate(result.error_groups[:10], start=1):
            first_s = grp.first_seen.strftime("%Y-%m-%d %H:%M:%SZ") if grp.first_seen else "N/A"
            last_s = grp.last_seen.strftime("%Y-%m-%d %H:%M:%SZ") if grp.last_seen else "N/A"
            lines.append(
                f"  #{idx} [{grp.fingerprint}] ({grp.count:,} occurrences) — {grp.category_name}"
            )
            lines.append(f"     Template   : {grp.template[:100]}")
            lines.append(
                f"     Services   : {', '.join(grp.services) or 'N/A'} | "
                f"Exception: {grp.exception_type or 'None'} | Code: {grp.error_code or 'None'}"
            )
            lines.append(
                f"     Window     : {first_s} -> {last_s} | Confidence: {grp.confidence.upper()}"
            )
            if grp.sample_locations:
                lines.append(f"     Locations  : {', '.join(grp.sample_locations[:4])}")
            lines.append(f"     Hint       : {grp.investigation_hint}")
            lines.append("")
    else:
        lines.append("  Zero recurring error groups identified.")

    if report_paths:
        lines.append(subsep)
        lines.append("  GENERATED REPORT ARTIFACTS")
        lines.append(subsep)
        for label, p in report_paths.items():
            lines.append(f"  {label:<22} : {p}")

    lines.append(sep)
    return "\n".join(lines)


def export_json_report(result: AnalysisResult, output_dir: str | Path) -> Path:
    """Write the complete analysis result to `report.json`."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / "report.json"
    json_path.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return json_path


def export_csv_reports(
    result: AnalysisResult,
    output_dir: str | Path,
    csv_formula_protection: bool = True,
) -> dict[str, Path]:
    """Export recurring error groups, anomaly alerts, time series, and file stats to CSV files."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: dict[str, Path] = {}

    def _write_csv(file_path: Path, headers: list[str], rows: list[list[Any]]) -> Path:
        with file_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(headers)
            for row in rows:
                writer.writerow(
                    [sanitize_csv_cell(cell, enabled=csv_formula_protection) for cell in row]
                )
        return file_path

    # 1. error_groups.csv
    eg_headers = [
        "fingerprint",
        "category_id",
        "category_name",
        "count",
        "first_seen",
        "last_seen",
        "services",
        "severities",
        "exception_type",
        "error_code",
        "confidence",
        "template",
        "sample_message",
        "source_files",
        "sample_locations",
        "investigation_hint",
    ]
    eg_rows: list[list[Any]] = []
    for g in result.error_groups:
        eg_rows.append(
            [
                g.fingerprint,
                g.category_id,
                g.category_name,
                g.count,
                g.first_seen.isoformat() if g.first_seen else "",
                g.last_seen.isoformat() if g.last_seen else "",
                ";".join(g.services),
                json.dumps(g.severity_distribution),
                g.exception_type or "",
                g.error_code or "",
                g.confidence,
                g.template,
                g.sample_messages[0] if g.sample_messages else "",
                ";".join(g.source_files),
                ";".join(g.sample_locations),
                g.investigation_hint,
            ]
        )
    paths["error_groups_csv"] = _write_csv(out_dir / "error_groups.csv", eg_headers, eg_rows)

    # 2. anomaly_alerts.csv
    al_headers = [
        "alert_id",
        "window_start",
        "window_end",
        "window_size",
        "alert_type",
        "severity_label",
        "observed_count",
        "baseline_mean",
        "baseline_median",
        "baseline_mad",
        "ratio_over_baseline",
        "modified_z_score",
        "threshold_limit",
        "top_service",
        "top_category",
        "top_fingerprint",
        "explanation",
    ]
    al_rows: list[list[Any]] = []
    for a in result.anomaly_alerts:
        al_rows.append(
            [
                a.alert_id,
                a.window_start.isoformat(),
                a.window_end.isoformat(),
                a.window_size,
                a.alert_type,
                a.severity_label,
                a.observed_count,
                round(a.baseline_mean, 3),
                round(a.baseline_median, 3),
                round(a.baseline_mad, 3),
                round(a.ratio_over_baseline, 3),
                round(a.modified_z_score, 3),
                a.threshold_limit,
                a.top_service,
                a.top_category,
                a.top_fingerprint,
                a.explanation,
            ]
        )
    paths["anomaly_alerts_csv"] = _write_csv(out_dir / "anomaly_alerts.csv", al_headers, al_rows)

    # 3. time_series.csv
    ts_headers = [
        "window_start",
        "total_events",
        "error_events",
        "warning_events",
        "rolling_baseline",
        "is_anomaly",
        "alert_type",
    ]
    ts_rows: list[list[Any]] = [
        [
            b.window_start.isoformat(),
            b.total_events,
            b.error_events,
            b.warning_events,
            round(b.rolling_baseline, 3),
            b.is_anomaly,
            b.alert_type or "",
        ]
        for b in result.time_series_buckets
    ]
    paths["time_series_csv"] = _write_csv(out_dir / "time_series.csv", ts_headers, ts_rows)

    # 4. file_ingestion_stats.csv
    fs_headers = [
        "file_path",
        "detected_format",
        "total_lines",
        "parsed_events",
        "multiline_events",
        "malformed_lines",
        "duplicate_events_skipped",
        "missing_timestamp_events",
        "encoding_errors",
        "status",
    ]
    fs_rows: list[list[Any]] = [
        [
            f.file_path,
            f.detected_format,
            f.total_lines,
            f.parsed_events,
            f.multiline_events,
            f.malformed_lines,
            f.duplicate_events_skipped,
            f.missing_timestamp_events,
            f.encoding_errors,
            f.status,
        ]
        for f in result.file_stats
    ]
    paths["file_stats_csv"] = _write_csv(out_dir / "file_ingestion_stats.csv", fs_headers, fs_rows)

    return paths


def export_html_report(
    result: AnalysisResult,
    output_dir: str | Path,
    chart_uris: dict[str, tuple[Path, str]] | None = None,
) -> Path:
    """Generate a standalone, offline-ready HTML report with embedded charts and filtering."""
    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    html_path = out_dir / "report.html"

    uris = {k: v[1] for k, v in (chart_uris or {}).items()}

    # Build answers to the 6 core operational questions
    top_group = result.error_groups[0] if result.error_groups else None
    what_failed = (
        f"{result.total_error_events:,} failure events across {len(result.error_groups)} unique "
        f"fingerprints. Top failure: [{safe_html(top_group.category_name)}] "
        f"{safe_html(top_group.template[:95])} ({top_group.count:,} occurrences)."
        if top_group
        else "Zero failure events detected across analyzed logs."
    )
    when_started = (
        f"Log window spans {safe_html(result.time_range_start.strftime('%Y-%m-%d %H:%M:%SZ'))} to "
        f"{safe_html(result.time_range_end.strftime('%Y-%m-%d %H:%M:%SZ'))}. "
        + (
            f"First top failure occurred at {safe_html(top_group.first_seen.strftime('%Y-%m-%d %H:%M:%SZ'))}."
            if top_group and top_group.first_seen
            else ""
        )
        if result.time_range_start and result.time_range_end
        else "No valid timestamps present."
    )
    err_pct = (result.total_error_events / max(result.total_events_analyzed, 1)) * 100.0
    how_frequent = (
        f"{result.total_error_events:,} errors out of {result.total_events_analyzed:,} events "
        f"({err_pct:.1f}% error rate); median {result.anomaly_diagnostics.get('global_median_errors_per_bucket', 0)} "
        f"errors per {safe_html(result.anomaly_diagnostics.get('time_window', '5min'))} window."
    )
    affected_srvs = [
        f"{safe_html(s)} ({c:,} errors)"
        for s, c in sorted(result.service_error_counts.items(), key=lambda x: x[1], reverse=True)
        if c > 0
    ]
    which_services = (
        ", ".join(affected_srvs[:6]) if affected_srvs else "No services experienced errors."
    )
    investigate_first = (
        f"1) {safe_html(result.high_priority_findings[0]['title'])} — "
        f"{safe_html(result.high_priority_findings[0]['recommendation'])}"
        if result.high_priority_findings
        else "No urgent failure investigations required."
    )

    # Priority findings rows
    findings_html_parts: list[str] = []
    for f in result.high_priority_findings:
        badge_cls = "badge-critical" if "P1" in f["priority"] else "badge-warn"
        findings_html_parts.append(
            f"""
            <tr>
              <td><span class="badge {badge_cls}">{safe_html(f["priority"])}</span></td>
              <td><strong>{safe_html(f["title"])}</strong><br><small class="muted">{safe_html(f["impact"])}</small></td>
              <td><code>{safe_html(f["first_seen"])}</code><br>to <code>{safe_html(f["last_seen"])}</code></td>
              <td>{safe_html(f["recommendation"])}</td>
            </tr>
            """
        )
    findings_rows_html = (
        "\n".join(findings_html_parts)
        if findings_html_parts
        else '<tr><td colspan="4" class="empty-cell">No high-priority failure findings recorded.</td></tr>'
    )

    # Anomaly alerts rows
    alert_html_parts: list[str] = []
    for a in result.anomaly_alerts:
        type_badge = (
            "badge-critical"
            if a.alert_type in ("combined", "confirmed_threshold")
            else "badge-warn"
        )
        alert_html_parts.append(
            f"""
            <tr>
              <td><code>{safe_html(a.alert_id)}</code></td>
              <td><span class="badge {type_badge}">{safe_html(a.alert_type)}</span></td>
              <td><code>{safe_html(a.window_start.strftime("%Y-%m-%d %H:%M:%SZ"))}</code> ({safe_html(a.window_size)})</td>
              <td><strong>{a.observed_count:,}</strong> (Threshold: {a.threshold_limit})</td>
              <td>Med: {a.baseline_median:.1f} / Mean: {a.baseline_mean:.1f}</td>
              <td><strong>{a.ratio_over_baseline:.1f}x</strong> (Mod-Z: {a.modified_z_score:.2f})</td>
              <td><code>{safe_html(a.top_service)}</code> / {safe_html(a.top_category)}</td>
              <td>{safe_html(a.explanation)}</td>
            </tr>
            """
        )
    alerts_rows_html = (
        "\n".join(alert_html_parts)
        if alert_html_parts
        else '<tr><td colspan="8" class="empty-cell">No statistical anomalies or threshold violations triggered.</td></tr>'
    )

    # Recurring error group cards/rows
    group_html_parts: list[str] = []
    categories_set: set[str] = set()
    for g in result.error_groups:
        categories_set.add(g.category_name)
        first_str = g.first_seen.strftime("%Y-%m-%d %H:%M:%SZ") if g.first_seen else "N/A"
        last_str = g.last_seen.strftime("%Y-%m-%d %H:%M:%SZ") if g.last_seen else "N/A"
        tb_block = ""
        if g.sample_tracebacks:
            tb_block = f'<details class="tb-details"><summary>View Sample Traceback</summary><pre class="tb-pre">{safe_html(g.sample_tracebacks[0])}</pre></details>'
        sample_msg_html = safe_html(g.sample_messages[0]) if g.sample_messages else ""
        conf_cls = (
            "badge-ok"
            if g.confidence == "high"
            else ("badge-warn" if g.confidence == "medium" else "badge-critical")
        )
        group_html_parts.append(
            f"""
            <tr class="error-group-row" data-category="{safe_html(g.category_name.lower())}" data-search="{safe_html((g.fingerprint + " " + g.category_name + " " + g.template + " " + " ".join(g.services) + " " + (g.exception_type or "")).lower())}">
              <td><code>{safe_html(g.fingerprint)}</code><br><span class="badge {conf_cls}" title="{safe_html(g.confidence_note)}">{safe_html(g.confidence)} conf</span></td>
              <td><strong>{safe_html(g.category_name)}</strong><br><small class="muted">{safe_html(g.exception_type or "No exception class")} {("[" + safe_html(g.error_code) + "]") if g.error_code else ""}</small></td>
              <td class="num-col"><strong>{g.count:,}</strong></td>
              <td><code>{safe_html(", ".join(g.services) or "unknown")}</code></td>
              <td><small>First: <code>{safe_html(first_str)}</code><br>Last: <code>{safe_html(last_str)}</code></small></td>
              <td>
                <div class="template-box"><code>{safe_html(g.template)}</code></div>
                <div class="sample-msg"><strong>Sample:</strong> {sample_msg_html}</div>
                <div class="trace-meta"><small><strong>Source Locations:</strong> {safe_html(", ".join(g.sample_locations[:4]) or "N/A")} | <strong>Code:</strong> {safe_html(", ".join(g.source_files[:3]) or "N/A")}</small></div>
                <div class="hint-box"><strong>Investigation Hint:</strong> {safe_html(g.investigation_hint)}</div>
                {tb_block}
              </td>
            </tr>
            """
        )
    groups_rows_html = (
        "\n".join(group_html_parts)
        if group_html_parts
        else '<tr><td colspan="6" class="empty-cell">No recurring error groups identified.</td></tr>'
    )

    cat_options_html = "\n".join(
        f'<option value="{safe_html(c.lower())}">{safe_html(c)}</option>'
        for c in sorted(categories_set)
    )

    # File ingestion diagnostics rows
    file_html_parts: list[str] = []
    for f_stat in result.file_stats:
        file_html_parts.append(
            f"""
            <tr>
              <td><code>{safe_html(f_stat.file_path)}</code></td>
              <td><span class="badge badge-neutral">{safe_html(f_stat.detected_format)}</span></td>
              <td class="num-col">{f_stat.total_lines:,}</td>
              <td class="num-col">{f_stat.parsed_events:,}</td>
              <td class="num-col">{f_stat.multiline_events:,}</td>
              <td class="num-col">{f_stat.malformed_lines:,}</td>
              <td class="num-col">{f_stat.missing_timestamp_events:,}</td>
              <td><span class="badge {"badge-ok" if f_stat.status == "ok" else "badge-warn"}">{safe_html(f_stat.status)}</span></td>
            </tr>
            """
        )
    files_rows_html = "\n".join(file_html_parts)

    def _chart_card(key: str, title: str) -> str:
        uri = uris.get(key, "")
        if not uri:
            return ""
        return f"""
        <div class="chart-card">
          <h3>{safe_html(title)}</h3>
          <img src="{uri}" alt="{safe_html(title)}" class="chart-img" />
        </div>
        """

    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Log Analysis &amp; Failure Classification Report — {safe_html(result.run_id)}</title>
  <style>
    :root {{
      --bg: #f8fafc;
      --card: #ffffff;
      --text: #0f172a;
      --muted: #475569;
      --border: #e2e8f0;
      --primary: #1e293b;
      --accent: #2563eb;
      --critical: #dc2626;
      --critical-bg: #fef2f2;
      --warn: #d97706;
      --warn-bg: #fffbeb;
      --ok: #059669;
      --ok-bg: #ecfdf5;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }}
    .navbar {{
      position: sticky;
      top: 0;
      z-index: 100;
      background: var(--primary);
      color: #ffffff;
      padding: 0.75rem 2rem;
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 1rem;
      box-shadow: 0 2px 6px rgba(0,0,0,0.12);
    }}
    .navbar-brand {{
      font-weight: 700;
      font-size: 1.1rem;
      letter-spacing: 0.01em;
    }}
    .navbar-links {{
      display: flex;
      gap: 1.2rem;
      flex-wrap: wrap;
    }}
    .navbar-links a {{
      color: #cbd5e1;
      text-decoration: none;
      font-size: 0.9rem;
      font-weight: 500;
    }}
    .navbar-links a:hover {{ color: #ffffff; }}
    .container {{
      max-width: 1360px;
      margin: 0 auto;
      padding: 1.75rem 2rem 3rem;
    }}
    .header-banner {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.4rem 1.75rem;
      margin-bottom: 1.5rem;
      display: flex;
      justify-content: space-between;
      align-items: flex-start;
      flex-wrap: wrap;
      gap: 1rem;
    }}
    .header-banner h1 {{
      margin: 0 0 0.35rem 0;
      font-size: 1.5rem;
      color: var(--primary);
    }}
    .meta-line {{
      color: var(--muted);
      font-size: 0.88rem;
    }}
    .kpi-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(195px, 1fr));
      gap: 1rem;
      margin-bottom: 1.75rem;
    }}
    .kpi-card {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.1rem 1.25rem;
      box-shadow: 0 1px 2px rgba(0,0,0,0.03);
    }}
    .kpi-label {{
      font-size: 0.78rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
      color: var(--muted);
      font-weight: 600;
    }}
    .kpi-value {{
      font-size: 1.75rem;
      font-weight: 800;
      margin: 0.25rem 0;
      color: var(--primary);
    }}
    .kpi-value.danger {{ color: var(--critical); }}
    .kpi-value.warn {{ color: var(--warn); }}
    .kpi-value.ok {{ color: var(--ok); }}
    .kpi-sub {{
      font-size: 0.8rem;
      color: var(--muted);
    }}
    section {{
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.5rem 1.75rem;
      margin-bottom: 1.75rem;
      box-shadow: 0 1px 3px rgba(0,0,0,0.03);
    }}
    section h2 {{
      margin-top: 0;
      font-size: 1.2rem;
      color: var(--primary);
      border-bottom: 1px solid var(--border);
      padding-bottom: 0.65rem;
      margin-bottom: 1.1rem;
    }}
    .qa-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
      gap: 1rem;
    }}
    .qa-box {{
      background: #f8fafc;
      border-left: 4px solid var(--accent);
      padding: 0.9rem 1.1rem;
      border-radius: 6px;
    }}
    .qa-box h4 {{
      margin: 0 0 0.3rem 0;
      font-size: 0.92rem;
      color: var(--primary);
    }}
    .qa-box p {{
      margin: 0;
      font-size: 0.88rem;
      color: #334155;
    }}
    .charts-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(540px, 1fr));
      gap: 1.25rem;
    }}
    .chart-card {{
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem;
      background: #ffffff;
    }}
    .chart-card h3 {{
      margin: 0 0 0.6rem 0;
      font-size: 0.98rem;
      color: var(--primary);
    }}
    .chart-img {{
      width: 100%;
      height: auto;
      display: block;
      border-radius: 4px;
    }}
    table {{
      width: 100%;
      border-collapse: collapse;
      font-size: 0.88rem;
    }}
    th, td {{
      text-align: left;
      padding: 0.7rem 0.75rem;
      border-bottom: 1px solid var(--border);
      vertical-align: top;
    }}
    th {{
      background: #f1f5f9;
      font-weight: 600;
      color: #334155;
      font-size: 0.8rem;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }}
    .num-col {{ text-align: right; font-variant-numeric: tabular-nums; }}
    .badge {{
      display: inline-block;
      padding: 0.2rem 0.55rem;
      border-radius: 999px;
      font-size: 0.75rem;
      font-weight: 700;
    }}
    .badge-critical {{ background: var(--critical-bg); color: var(--critical); border: 1px solid #fecaca; }}
    .badge-warn {{ background: var(--warn-bg); color: var(--warn); border: 1px solid #fde68a; }}
    .badge-ok {{ background: var(--ok-bg); color: var(--ok); border: 1px solid #a7f3d0; }}
    .badge-neutral {{ background: #f1f5f9; color: #334155; border: 1px solid #cbd5e1; }}
    .template-box {{
      background: #f1f5f9;
      padding: 0.45rem 0.65rem;
      border-radius: 5px;
      margin-bottom: 0.4rem;
      word-break: break-word;
    }}
    .sample-msg {{
      font-size: 0.84rem;
      color: #334155;
      margin-bottom: 0.35rem;
      word-break: break-word;
    }}
    .trace-meta {{
      color: var(--muted);
      margin-bottom: 0.35rem;
    }}
    .hint-box {{
      background: #eff6ff;
      border-left: 3px solid var(--accent);
      padding: 0.4rem 0.65rem;
      font-size: 0.82rem;
      color: #1e3a8a;
      border-radius: 4px;
      margin-top: 0.35rem;
    }}
    .tb-details {{
      margin-top: 0.45rem;
    }}
    .tb-details summary {{
      cursor: pointer;
      color: var(--accent);
      font-size: 0.82rem;
      font-weight: 600;
    }}
    .tb-pre {{
      background: #0f172a;
      color: #e2e8f0;
      padding: 0.75rem;
      border-radius: 6px;
      font-size: 0.78rem;
      overflow-x: auto;
      margin: 0.4rem 0 0;
    }}
    .filter-bar {{
      display: flex;
      gap: 0.75rem;
      margin-bottom: 1rem;
      flex-wrap: wrap;
    }}
    .filter-input, .filter-select {{
      padding: 0.5rem 0.75rem;
      border: 1px solid #cbd5e1;
      border-radius: 6px;
      font-size: 0.88rem;
    }}
    .filter-input {{ flex: 1; min-width: 240px; }}
    .muted {{ color: var(--muted); }}
    .empty-cell {{ text-align: center; color: var(--muted); padding: 1.5rem; }}
    footer {{
      text-align: center;
      color: var(--muted);
      font-size: 0.82rem;
      margin-top: 2rem;
    }}
  </style>
</head>
<body>
  <nav class="navbar">
    <div class="navbar-brand">Python Log Analyzer &amp; Failure Classifier</div>
    <div class="navbar-links">
      <a href="#questions">Operational Summary</a>
      <a href="#priority">Priority Findings</a>
      <a href="#charts">Visualizations</a>
      <a href="#anomalies">Anomaly Spikes ({len(result.anomaly_alerts)})</a>
      <a href="#groups">Recurring Failures ({len(result.error_groups)})</a>
      <a href="#ingestion">Ingestion &amp; Diagnostics</a>
    </div>
  </nav>

  <div class="container">
    <div class="header-banner">
      <div>
        <h1>Application Log Analysis &amp; Anomaly Report</h1>
        <div class="meta-line">
          Run ID: <code>{safe_html(result.run_id)}</code> &bull;
          Generated: <code>{safe_html(result.generated_at.strftime("%Y-%m-%d %H:%M:%SZ"))}</code> &bull;
          Window: <code>{safe_html(result.time_range_start.strftime("%Y-%m-%d %H:%M:%SZ") if result.time_range_start else "N/A")}</code>
          to <code>{safe_html(result.time_range_end.strftime("%Y-%m-%d %H:%M:%SZ") if result.time_range_end else "N/A")}</code>
        </div>
      </div>
      <div>
        <span class="badge {"badge-critical" if result.anomaly_alerts else "badge-ok"}">
          {len(result.anomaly_alerts)} Active Anomaly Alert(s)
        </span>
        <span class="badge badge-neutral">{result.redactions_applied} Secrets Redacted</span>
      </div>
    </div>

    <div class="kpi-grid">
      <div class="kpi-card">
        <div class="kpi-label">Total Events Analyzed</div>
        <div class="kpi-value">{result.total_events_analyzed:,}</div>
        <div class="kpi-sub">From {result.total_lines_read:,} raw lines in {result.total_files_scanned} file(s)</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Error &amp; Critical Events</div>
        <div class="kpi-value {"danger" if result.total_error_events > 0 else "ok"}">{result.total_error_events:,}</div>
        <div class="kpi-sub">{err_pct:.1f}% of total analyzed volume</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Warning Events</div>
        <div class="kpi-value warn">{result.total_warning_events:,}</div>
        <div class="kpi-sub">Deduplicated overlaps: {result.duplicate_events_skipped:,}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Unique Error Groups</div>
        <div class="kpi-value">{len(result.error_groups)}</div>
        <div class="kpi-sub">Fingerprinted with variable masking</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Anomaly Spikes</div>
        <div class="kpi-value {"danger" if result.anomaly_alerts else "ok"}">{len(result.anomaly_alerts)}</div>
        <div class="kpi-sub">Window size: {safe_html(result.anomaly_diagnostics.get("time_window", "5min"))}</div>
      </div>
      <div class="kpi-card">
        <div class="kpi-label">Parser Diagnostics</div>
        <div class="kpi-value">{result.malformed_lines_count}</div>
        <div class="kpi-sub">Malformed lines ({result.missing_timestamp_count} missing timestamps)</div>
      </div>
    </div>

    <section id="questions">
      <h2>Executive Triage — Key Operational Answers</h2>
      <div class="qa-grid">
        <div class="qa-box">
          <h4>1. What failed?</h4>
          <p>{what_failed}</p>
        </div>
        <div class="qa-box">
          <h4>2. When did it start?</h4>
          <p>{when_started}</p>
        </div>
        <div class="qa-box">
          <h4>3. How frequently is it happening?</h4>
          <p>{how_frequent}</p>
        </div>
        <div class="qa-box">
          <h4>4. Which services are affected?</h4>
          <p>{which_services}</p>
        </div>
        <div class="qa-box">
          <h4>5. Is the situation getting worse?</h4>
          <p>{safe_html(result.trend_summary)}</p>
        </div>
        <div class="qa-box">
          <h4>6. Which failures should be investigated first?</h4>
          <p>{investigate_first}</p>
        </div>
      </div>
    </section>

    <section id="priority">
      <h2>High-Priority Findings &amp; Recommended Triage Order</h2>
      <table>
        <thead>
          <tr>
            <th style="width: 150px;">Priority</th>
            <th>Finding &amp; Scope</th>
            <th style="width: 220px;">Observed Window</th>
            <th>Grounded Investigation Hint</th>
          </tr>
        </thead>
        <tbody>
          {findings_rows_html}
        </tbody>
      </table>
    </section>

    <section id="charts">
      <h2>Visual Analytics &amp; Error Trends</h2>
      <div class="charts-grid">
        {_chart_card("errors_over_time", "1. Errors & Warnings Over Time")}
        {_chart_card("anomaly_spikes", "2. Detected Anomaly Spikes & Rolling Baseline")}
        {_chart_card("failure_categories", "3. Failure Categories Breakdown")}
        {_chart_card("top_recurring_failures", "4. Top Recurring Failure Fingerprints")}
        {_chart_card("errors_by_service", "5. Errors & Volume by Service")}
        {_chart_card("severity_distribution", "6. Log Severity Distribution")}
      </div>
    </section>

    <section id="anomalies">
      <h2>Spike &amp; Statistical Anomaly Detection Details</h2>
      <p class="muted" style="margin-top:0;">
        {safe_html(result.anomaly_diagnostics.get("note", ""))}
        Confirmed threshold violations exceed the configured ceiling ({result.anomaly_diagnostics.get("absolute_threshold", 25)} errors/window);
        statistical anomaly indicators exceed both the robust Median/MAD modified Z-score (&ge; {result.anomaly_diagnostics.get("mad_z_threshold", 3.5)})
        and ratio (&ge; {result.anomaly_diagnostics.get("ratio_threshold", 3.0)}x baseline).
      </p>
      <table>
        <thead>
          <tr>
            <th>Alert ID</th>
            <th>Detection Type</th>
            <th>Time Window (UTC)</th>
            <th>Observed</th>
            <th>Baseline</th>
            <th>Ratio / Mod-Z</th>
            <th>Primary Driver</th>
            <th>Explanation</th>
          </tr>
        </thead>
        <tbody>
          {alerts_rows_html}
        </tbody>
      </table>
    </section>

    <section id="groups">
      <h2>Recurring Failure Groups (Fingerprinted &amp; Deduplicated)</h2>
      <div class="filter-bar">
        <input type="text" id="groupSearch" class="filter-input" placeholder="Filter by keyword, fingerprint, service, or exception type..." oninput="filterGroups()" />
        <select id="categoryFilter" class="filter-select" onchange="filterGroups()">
          <option value="">All Failure Categories</option>
          {cat_options_html}
        </select>
      </div>
      <table id="groupsTable">
        <thead>
          <tr>
            <th style="width: 130px;">Fingerprint</th>
            <th style="width: 210px;">Category &amp; Exception</th>
            <th style="width: 90px;" class="num-col">Count</th>
            <th style="width: 150px;">Services</th>
            <th style="width: 195px;">First / Last Seen</th>
            <th>Normalized Template, Sample &amp; Investigation Hint</th>
          </tr>
        </thead>
        <tbody>
          {groups_rows_html}
        </tbody>
      </table>
    </section>

    <section id="ingestion">
      <h2>File Ingestion &amp; Parser Diagnostics</h2>
      <table>
        <thead>
          <tr>
            <th>Log File Path</th>
            <th>Detected Format</th>
            <th class="num-col">Total Lines</th>
            <th class="num-col">Parsed Events</th>
            <th class="num-col">Multiline Tracebacks</th>
            <th class="num-col">Malformed Lines</th>
            <th class="num-col">Missing Timestamps</th>
            <th>Status</th>
          </tr>
        </thead>
        <tbody>
          {files_rows_html}
        </tbody>
      </table>
    </section>

    <footer>
      Generated offline by <strong>Python Log Analyzer &amp; Failure Classifier v1.0.0</strong> &bull;
      Local-first execution &bull; Sensitive values automatically redacted.
    </footer>
  </div>

  <script>
    function filterGroups() {{
      var q = (document.getElementById('groupSearch').value || '').toLowerCase();
      var cat = (document.getElementById('categoryFilter').value || '').toLowerCase();
      var rows = document.querySelectorAll('.error-group-row');
      for (var i = 0; i < rows.length; i++) {{
        var row = rows[i];
        var rowCat = row.getAttribute('data-category') || '';
        var rowSearch = row.getAttribute('data-search') || '';
        var matchCat = !cat || rowCat === cat;
        var matchQ = !q || rowSearch.indexOf(q) !== -1;
        row.style.display = (matchCat && matchQ) ? '' : 'none';
      }}
    }}
  </script>
</body>
</html>
"""
    html_path.write_text(html_content, encoding="utf-8")
    return html_path
