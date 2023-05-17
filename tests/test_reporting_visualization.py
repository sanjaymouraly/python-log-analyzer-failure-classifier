"""Tests for CSV, JSON, HTML, and PNG visualization report generation."""

from __future__ import annotations

import csv
import json
from pathlib import Path

from log_analyzer.config import AnalyzerConfig
from log_analyzer.pipeline import run_analysis_pipeline
from log_analyzer.reporter import format_terminal_summary


def test_exports_and_xss_csv_injection_safety(
    tmp_path: Path, default_config: AnalyzerConfig
) -> None:
    log_file = tmp_path / "security_export.log"
    log_file.write_text(
        "2026-10-16 10:00:00,100 - web.api - ERROR - =cmd|' /C calc'!A0 <script>alert(\"xss\")</script> Database error\n"
        "2026-10-16 10:05:00,100 - web.api - INFO - Normal request completed\n",
        encoding="utf-8",
    )

    out_dir = tmp_path / "reports"
    result, paths = run_analysis_pipeline(
        input_paths=[log_file],
        config=default_config,
        output_dir=out_dir,
        export_formats={"all"},
    )

    # Check terminal summary
    summary = format_terminal_summary(result, report_paths=paths)
    assert "EXECUTIVE SUMMARY" in summary
    assert "Database Errors" in summary

    # Check JSON report
    json_path = paths["json_report"]
    assert json_path.exists()
    parsed_json = json.loads(json_path.read_text(encoding="utf-8"))
    assert parsed_json["summary"]["total_error_events"] == 1

    # Check CSV report formula injection sanitization
    eg_csv = paths["error_groups_csv"]
    assert eg_csv.exists()
    with eg_csv.open("r", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert len(rows) == 1
    assert rows[0]["sample_message"].startswith("'=cmd")

    # Check HTML report XSS escaping and embedded base64 charts
    html_path = paths["html_report"]
    assert html_path.exists()
    html_text = html_path.read_text(encoding="utf-8")
    assert '<script>alert("xss")</script>' not in html_text
    assert "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;" in html_text
    assert "data:image/png;base64," in html_text

    # Check all 6 PNG charts exist and have valid PNG magic bytes
    for key in (
        "chart_errors_over_time",
        "chart_severity_distribution",
        "chart_top_recurring_failures",
        "chart_failure_categories",
        "chart_errors_by_service",
        "chart_anomaly_spikes",
    ):
        p = paths[key]
        assert p.exists()
        raw = p.read_bytes()
        assert raw.startswith(b"\x89PNG\r\n\x1a\n")
        assert len(raw) > 1000
