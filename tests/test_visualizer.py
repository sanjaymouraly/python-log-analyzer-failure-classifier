"""Unit tests for Matplotlib chart generation."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

from log_analyzer.models import (
    AnalysisResult,
    AnomalyAlert,
    ErrorGroup,
    FileIngestionStats,
    TimeBucketMetric,
)
from log_analyzer.visualizer import generate_all_charts


def _make_result() -> AnalysisResult:
    return AnalysisResult(
        run_id="run-test-001",
        generated_at=datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC),
        input_paths=["/tmp/test.log"],
        config_summary={},
        total_files_scanned=1,
        total_events_parsed=95,
        total_events_analyzed=90,
        total_error_events=10,
        total_warning_events=5,
        severity_counts={"ERROR": 10, "WARNING": 5, "INFO": 80},
        category_counts={"database": 6, "auth": 4},
        service_counts={"api": 50, "worker": 40},
        service_error_counts={"api": 6, "worker": 4},
        error_groups=[
            ErrorGroup(
                fingerprint="abc123",
                template="Database connection failed",
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
                sample_messages=["Database connection failed"],
                confidence="high",
            ),
            ErrorGroup(
                fingerprint="def456",
                template="Authentication failed",
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
                sample_messages=["Authentication failed"],
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
                explanation="Spike detected",
            ),
        ],
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
                total_lines=100,
                parsed_events=95,
            ),
        ],
    )


class TestGenerateAllCharts:
    def test_generates_all_charts(self, tmp_path: Path):
        result = _make_result()
        charts = generate_all_charts(result, tmp_path)
        assert len(charts) == 6
        for _name, (path, data_uri) in charts.items():
            assert path.exists()
            assert path.suffix == ".png"
            assert data_uri.startswith("data:image/png;base64,")

    def test_chart_keys(self, tmp_path: Path):
        result = _make_result()
        charts = generate_all_charts(result, tmp_path)
        expected_keys = {
            "errors_over_time",
            "severity_distribution",
            "top_recurring_failures",
            "failure_categories",
            "errors_by_service",
            "anomaly_spikes",
        }
        assert set(charts.keys()) == expected_keys

    def test_charts_have_nonzero_size(self, tmp_path: Path):
        result = _make_result()
        charts = generate_all_charts(result, tmp_path)
        for _name, (path, _) in charts.items():
            assert path.stat().st_size > 0

    def test_empty_result_charts(self, tmp_path: Path):
        result = AnalysisResult(
            run_id="run-empty",
            generated_at=datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC),
            input_paths=[],
            config_summary={},
        )
        charts = generate_all_charts(result, tmp_path)
        assert len(charts) == 6
        for _name, (path, data_uri) in charts.items():
            assert path.exists()
            assert data_uri.startswith("data:image/png;base64,")

    def test_creates_output_directory(self, tmp_path: Path):
        result = _make_result()
        chart_dir = tmp_path / "new_charts" / "nested"
        charts = generate_all_charts(result, chart_dir)
        assert chart_dir.exists()
        for _name, (path, _) in charts.items():
            assert path.exists()
