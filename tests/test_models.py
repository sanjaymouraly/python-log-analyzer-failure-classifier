"""Unit tests for data models: LogEvent, severity helpers, and serialization."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from log_analyzer.models import (
    AnomalyAlert,
    ErrorGroup,
    FileIngestionStats,
    LogEvent,
    ParseErrorRecord,
    TimeBucketMetric,
    normalize_severity,
    severity_rank,
)


def _make_event(**kwargs) -> LogEvent:
    defaults = {
        "event_id": 1,
        "timestamp": datetime(2026, 1, 1, tzinfo=UTC),
        "raw_timestamp": "2026-01-01T00:00:00+00:00",
        "timezone_name": "UTC",
        "severity": "ERROR",
        "service": "test-service",
        "logger": "test.logger",
        "message": "Test error message",
    }
    defaults.update(kwargs)
    return LogEvent(**defaults)


class TestNormalizeSeverity:
    @pytest.mark.parametrize(
        "raw,expected",
        [
            ("ERROR", "ERROR"),
            ("error", "ERROR"),
            ("Error", "ERROR"),
            ("ERR", "ERROR"),
            ("err", "ERROR"),
            ("WARNING", "WARNING"),
            ("WARN", "WARNING"),
            ("wrn", "WARNING"),
            ("INFO", "INFO"),
            ("information", "INFO"),
            ("DEBUG", "DEBUG"),
            ("DBG", "DEBUG"),
            ("TRACE", "DEBUG"),
            ("CRITICAL", "CRITICAL"),
            ("FATAL", "CRITICAL"),
            ("EMERG", "CRITICAL"),
            ("UNKNOWN", "UNKNOWN"),
            ("", "UNKNOWN"),
            (None, "UNKNOWN"),
        ],
    )
    def test_severity_aliases(self, raw, expected):
        assert normalize_severity(raw) == expected

    def test_custom_default(self):
        assert normalize_severity(None, default="INFO") == "INFO"
        assert normalize_severity("", default="DEBUG") == "DEBUG"


class TestSeverityRank:
    @pytest.mark.parametrize(
        "severity,expected",
        [
            ("CRITICAL", 50),
            ("ERROR", 40),
            ("WARNING", 30),
            ("INFO", 20),
            ("DEBUG", 10),
            ("UNKNOWN", 0),
            ("NONEXISTENT", 0),
        ],
    )
    def test_ranks(self, severity, expected):
        assert severity_rank(severity) == expected

    def test_all_ranks_positive_for_known(self):
        for sev in ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"):
            assert severity_rank(sev) > 0


class TestLogEvent:
    def test_is_failure_default_threshold(self):
        assert _make_event(severity="ERROR").is_failure() is True
        assert _make_event(severity="CRITICAL").is_failure() is True
        assert _make_event(severity="WARNING").is_failure() is False
        assert _make_event(severity="INFO").is_failure() is False

    def test_is_failure_custom_threshold(self):
        assert _make_event(severity="WARNING").is_failure(min_severity="WARNING") is True
        assert _make_event(severity="INFO").is_failure(min_severity="WARNING") is False

    def test_full_text_includes_traceback(self):
        event = _make_event(message="Error occurred", traceback="Traceback...\n  File ...")
        assert "Error occurred" in event.full_text
        assert "Traceback" in event.full_text

    def test_full_text_without_traceback(self):
        event = _make_event(message="Simple error")
        assert event.full_text == "Simple error"

    def test_to_dict_contains_key_fields(self):
        event = _make_event()
        d = event.to_dict()
        assert d["event_id"] == 1
        assert d["severity"] == "ERROR"
        assert d["service"] == "test-service"
        assert d["message"] == "Test error message"
        assert d["category_id"] == "normal_operation"

    def test_to_dict_with_optional_fields(self):
        event = _make_event(
            exception_type="ValueError",
            error_code="ERR_001",
            source_file="app.py",
            source_line=42,
            request_id="req-abc-123",
        )
        d = event.to_dict()
        assert d["exception_type"] == "ValueError"
        assert d["error_code"] == "ERR_001"
        assert d["source_file"] == "app.py"
        assert d["source_line"] == 42
        assert d["request_id"] == "req-abc-123"

    def test_defaults(self):
        event = _make_event()
        assert event.traceback is None
        assert event.exception_type is None
        assert event.error_code is None
        assert event.source_file is None
        assert event.source_line is None
        assert event.request_id is None
        assert event.log_file == ""
        assert event.log_line_number == 0
        assert event.parser_format == "unknown"
        assert event.fingerprint == ""
        assert event.timestamp_valid is True
        assert event.extra_metadata == {}


class TestFileIngestionStats:
    def test_defaults(self):
        stats = FileIngestionStats(file_path="/tmp/test.log")
        assert stats.total_lines == 0
        assert stats.parsed_events == 0
        assert stats.malformed_lines == 0
        assert stats.status == "ok"
        assert stats.error_message is None

    def test_to_dict(self):
        stats = FileIngestionStats(file_path="/tmp/test.log", total_lines=100, parsed_events=95)
        d = stats.to_dict()
        assert d["file_path"] == "/tmp/test.log"
        assert d["total_lines"] == 100
        assert d["parsed_events"] == 95


class TestParseErrorRecord:
    def test_to_dict(self):
        rec = ParseErrorRecord(log_file="test.log", line_number=5, raw_preview="bad line", reason="parse error")
        d = rec.to_dict()
        assert d["log_file"] == "test.log"
        assert d["line_number"] == 5
        assert d["reason"] == "parse error"


class TestErrorGroup:
    def test_to_dict(self):
        group = ErrorGroup(
            fingerprint="abc123",
            template="Test error <NUM>",
            category_id="application",
            category_name="Application Errors",
            exception_type="ValueError",
            error_code=None,
            count=5,
            first_seen=datetime(2026, 1, 1, tzinfo=UTC),
            last_seen=datetime(2026, 1, 2, tzinfo=UTC),
            services=["svc1"],
            severity_distribution={"ERROR": 5},
            source_files=["app.py"],
            log_files=["app.log"],
            sample_messages=["Test error 1"],
            confidence="high",
        )
        d = group.to_dict()
        assert d["fingerprint"] == "abc123"
        assert d["count"] == 5
        assert d["services"] == ["svc1"]
        assert d["confidence"] == "high"


class TestAnomalyAlert:
    def test_to_dict(self):
        alert = AnomalyAlert(
            alert_id="alert-1",
            window_start=datetime(2026, 1, 1, tzinfo=UTC),
            window_end=datetime(2026, 1, 1, 5, tzinfo=UTC),
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
        )
        d = alert.to_dict()
        assert d["alert_id"] == "alert-1"
        assert d["observed_count"] == 50
        assert d["alert_type"] == "confirmed_threshold"


class TestTimeBucketMetric:
    def test_to_dict(self):
        metric = TimeBucketMetric(
            window_start=datetime(2026, 1, 1, tzinfo=UTC),
            total_events=100,
            error_events=10,
            warning_events=5,
            is_anomaly=True,
            alert_type="statistical_anomaly",
        )
        d = metric.to_dict()
        assert d["total_events"] == 100
        assert d["error_events"] == 10
        assert d["is_anomaly"] is True
