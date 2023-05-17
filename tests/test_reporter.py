"""Unit tests for report generation: JSON, CSV, HTML, and terminal output."""

from __future__ import annotations

import csv
import json
from datetime import UTC, datetime
from pathlib import Path

from log_analyzer.models import (
    AnalysisResult,
    AnomalyAlert,
    ErrorGroup,
    FileIngestionStats,
    ParseErrorRecord,
    TimeBucketMetric,
)
from log_analyzer.reporter import (
    export_csv_reports,
    export_html_report,
    export_json_report,
    format_terminal_summary,
)


def _make_result() -> AnalysisResult:
    return AnalysisResult(
        run_id="run-test-001",
        generated_at=datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC),
        input_paths=["/tmp/test.log"],
        config_summary={"encoding": "utf-8", "top_n": 15},
        total_files_scanned=1,
        total_files_skipped_incremental=0,
        total_lines_read=100,
        total_events_parsed=95,
        total_events_analyzed=90,
        total_error_events=10,
        total_warning_events=5,
        malformed_lines_count=2,
        missing_timestamp_count=1,
        duplicate_events_skipped=0,
        filtered_events_skipped=0,
        redactions_applied=3,
        time_range_start=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
        time_range_end=datetime(2026, 1, 1, 13, 0, 0, tzinfo=UTC),
        severity_counts={"ERROR": 10, "WARNING": 5, "INFO": 80},
        category_counts={"database": 6, "auth": 4},
        service_counts={"api": 50, "worker": 40},
        service_error_counts={"api": 6, "worker": 4},
        error_groups=[
            ErrorGroup(
                fingerprint="abc123",
                template="Database connection failed to <IP>",
                category_id="database",
                category_name="Database Errors",
                exception_type="ConnectionError",
                error_code="ERR_001",
                count=6,
                first_seen=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
                last_seen=datetime(2026, 1, 1, 12, 30, 0, tzinfo=UTC),
                services=["api"],
                severity_distribution={"ERROR": 6},
                source_files=["db.py"],
                log_files=["app.log"],
                sample_messages=["Database connection failed to 192.168.1.1"],
                confidence="high",
                investigation_hint="Check database connectivity",
            ),
            ErrorGroup(
                fingerprint="def456",
                template="Authentication failed for user <NUM>",
                category_id="auth",
                category_name="Authentication Errors",
                exception_type="AuthError",
                error_code="AUTH_001",
                count=4,
                first_seen=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
                last_seen=datetime(2026, 1, 1, 12, 30, 0, tzinfo=UTC),
                services=["api"],
                severity_distribution={"ERROR": 4},
                source_files=["auth.py"],
                log_files=["app.log"],
                sample_messages=["Authentication failed for user 123"],
                confidence="high",
            ),
        ],
        anomaly_alerts=[
            AnomalyAlert(
                alert_id="alert-1",
                window_start=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
                window_end=datetime(2026, 1, 1, 12, 5, 0, tzinfo=UTC),
                window_size="5min",
                alert_type="confirmed_threshold",
                severity_label="CRITICAL",
                observed_count=50,
                baseline_mean=5.0,
                baseline_median=4.0,
                baseline_mad=2.0,
                ratio_over_baseline=10.0,
                modified_z_score=5.0,
                threshold_limit=25,
                explanation="Error count exceeded absolute threshold",
            ),
        ],
        anomaly_diagnostics={
            "status": "ok",
            "time_window": "5min",
            "total_buckets": 12,
            "insufficient_history": False,
        },
        time_series_buckets=[
            TimeBucketMetric(
                window_start=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
                total_events=20,
                error_events=5,
                warning_events=2,
            ),
            TimeBucketMetric(
                window_start=datetime(2026, 1, 1, 12, 5, 0, tzinfo=UTC),
                total_events=15,
                error_events=50,
                warning_events=1,
                is_anomaly=True,
                alert_type="confirmed_threshold",
            ),
        ],
        file_stats=[
            FileIngestionStats(
                file_path="/tmp/test.log",
                detected_format="python",
                total_lines=100,
                parsed_events=95,
                malformed_lines=2,
            ),
        ],
        parse_errors=[
            ParseErrorRecord(log_file="/tmp/test.log", line_number=5, raw_preview="bad line", reason="parse error"),
        ],
        high_priority_findings=[
            {
                "priority": "P1",
                "title": "Database connection failures",
                "impact": "6 errors in 30 minutes",
                "first_seen": "2026-01-01T12:00:00+00:00",
                "last_seen": "2026-01-01T12:30:00+00:00",
                "recommendation": "Investigate database connectivity",
            },
        ],
        trend_summary="Intermittent Spikes",
    )


class TestExportJsonReport:
    def test_creates_json_file(self, tmp_path: Path):
        result = _make_result()
        path = export_json_report(result, tmp_path)
        assert path.exists()
        assert path.suffix == ".json"

    def test_json_contains_summary(self, tmp_path: Path):
        result = _make_result()
        path = export_json_report(result, tmp_path)
        with open(path) as f:
            data = json.load(f)
        assert data["run_id"] == "run-test-001"
        assert data["summary"]["total_events_parsed"] == 95
        assert data["summary"]["total_error_events"] == 10

    def test_json_contains_error_groups(self, tmp_path: Path):
        result = _make_result()
        path = export_json_report(result, tmp_path)
        with open(path) as f:
            data = json.load(f)
        assert len(data["error_groups"]) == 2

    def test_json_contains_anomaly_alerts(self, tmp_path: Path):
        result = _make_result()
        path = export_json_report(result, tmp_path)
        with open(path) as f:
            data = json.load(f)
        assert len(data["anomaly_alerts"]) == 1

    def test_json_valid_structure(self, tmp_path: Path):
        result = _make_result()
        path = export_json_report(result, tmp_path)
        with open(path) as f:
            data = json.load(f)
        assert "run_id" in data
        assert "generated_at" in data
        assert "summary" in data
        assert "error_groups" in data
        assert "anomaly_alerts" in data


class TestExportCsvReports:
    def test_creates_csv_files(self, tmp_path: Path):
        result = _make_result()
        paths = export_csv_reports(result, tmp_path)
        assert "error_groups_csv" in paths
        assert "anomaly_alerts_csv" in paths
        assert "time_series_csv" in paths
        assert "file_stats_csv" in paths
        for path in paths.values():
            assert path.exists()

    def test_error_groups_csv_content(self, tmp_path: Path):
        result = _make_result()
        paths = export_csv_reports(result, tmp_path)
        with open(paths["error_groups_csv"], newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 2
        assert rows[0]["fingerprint"] == "abc123"
        assert rows[0]["count"] == "6"

    def test_anomaly_alerts_csv_content(self, tmp_path: Path):
        result = _make_result()
        paths = export_csv_reports(result, tmp_path)
        with open(paths["anomaly_alerts_csv"], newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["alert_type"] == "confirmed_threshold"

    def test_time_series_csv_content(self, tmp_path: Path):
        result = _make_result()
        paths = export_csv_reports(result, tmp_path)
        with open(paths["time_series_csv"], newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 2

    def test_file_stats_csv_content(self, tmp_path: Path):
        result = _make_result()
        paths = export_csv_reports(result, tmp_path)
        with open(paths["file_stats_csv"], newline="") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
        assert len(rows) == 1
        assert rows[0]["file_path"] == "/tmp/test.log"


class TestExportHtmlReport:
    def test_creates_html_file(self, tmp_path: Path):
        result = _make_result()
        path = export_html_report(result, tmp_path)
        assert path.exists()
        assert path.suffix == ".html"

    def test_html_contains_title(self, tmp_path: Path):
        result = _make_result()
        path = export_html_report(result, tmp_path)
        content = path.read_text(encoding="utf-8")
        assert "<title>" in content
        assert "Log Analysis" in content

    def test_html_contains_summary(self, tmp_path: Path):
        result = _make_result()
        path = export_html_report(result, tmp_path)
        content = path.read_text(encoding="utf-8")
        assert "total_events_parsed" in content or "95" in content

    def test_html_contains_error_groups(self, tmp_path: Path):
        result = _make_result()
        path = export_html_report(result, tmp_path)
        content = path.read_text(encoding="utf-8")
        assert "Database connection failed" in content

    def test_html_contains_anomaly_alerts(self, tmp_path: Path):
        result = _make_result()
        path = export_html_report(result, tmp_path)
        content = path.read_text(encoding="utf-8")
        assert "confirmed_threshold" in content or "CRITICAL" in content

    def test_html_escapes_special_chars(self, tmp_path: Path):
        result = _make_result()
        result.error_groups[0].template = "Error <script>alert('xss')</script> in module"
        path = export_html_report(result, tmp_path)
        content = path.read_text(encoding="utf-8")
        assert "<script>alert" not in content

    def test_html_with_charts(self, tmp_path: Path):
        result = _make_result()
        chart_dir = tmp_path / "charts"
        chart_dir.mkdir()
        # Create dummy chart files
        chart_paths = {}
        for name in ["errors_over_time", "severity_distribution"]:
            p = chart_dir / f"{name}.png"
            p.write_bytes(b"")
            chart_paths[name] = (p, "data:image/png;base64,")
        path = export_html_report(result, tmp_path, chart_uris=chart_paths)
        content = path.read_text(encoding="utf-8")
        # Charts are embedded as base64 images; verify the report contains image tags
        assert "<img" in content or "base64" in content or "chart" in content.lower()


class TestFormatTerminalSummary:
    def test_summary_contains_key_metrics(self):
        result = _make_result()
        summary = format_terminal_summary(result)
        assert "95" in summary  # total events
        assert "10" in summary  # error events
        assert "run-test-001" in summary

    def test_summary_contains_error_groups(self):
        result = _make_result()
        summary = format_terminal_summary(result)
        assert "Database connection failed" in summary

    def test_summary_contains_anomaly_alerts(self):
        result = _make_result()
        summary = format_terminal_summary(result)
        assert "CRITICAL" in summary or "alert" in summary.lower()

    def test_summary_with_report_paths(self):
        result = _make_result()
        paths = {"json_report": Path("/tmp/report.json"), "html_report": Path("/tmp/report.html")}
        summary = format_terminal_summary(result, report_paths=paths)
        assert "report.json" in summary

    def test_summary_empty_result(self):
        result = AnalysisResult(
            run_id="run-empty",
            generated_at=datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC),
            input_paths=[],
            config_summary={},
        )
        summary = format_terminal_summary(result)
        assert "run-empty" in summary
