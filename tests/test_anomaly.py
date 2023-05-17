"""Unit tests for statistical anomaly and spike detection."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from log_analyzer.anomaly import detect_anomalies_and_series
from log_analyzer.config import AnomalyConfig
from log_analyzer.models import LogEvent


def _make_event(**kwargs) -> LogEvent:
    defaults = {
        "event_id": 1,
        "timestamp": datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
        "raw_timestamp": "2026-01-01T12:00:00+00:00",
        "timezone_name": "UTC",
        "severity": "ERROR",
        "service": "test-service",
        "logger": "test.logger",
        "message": "Test error message",
    }
    defaults.update(kwargs)
    return LogEvent(**defaults)


def _make_config(**kwargs) -> AnomalyConfig:
    defaults = {
        "time_window": "5min",
        "rolling_window_buckets": 6,
        "min_history_buckets": 6,
        "min_spike_count": 8,
        "absolute_threshold": 25,
        "ratio_threshold": 3.0,
        "mad_z_threshold": 3.5,
    }
    defaults.update(kwargs)
    return AnomalyConfig(**defaults)


class TestDetectAnomaliesAndSeries:
    def test_no_timestamped_events(self):
        events = [_make_event(timestamp=None)]
        metrics, alerts, diagnostics, trend = detect_anomalies_and_series(events, _make_config())
        assert len(metrics) == 0
        assert len(alerts) == 0
        assert diagnostics["status"] == "no_timestamped_events"
        assert trend == "Insufficient timestamped data"

    def test_empty_events(self):
        metrics, alerts, diagnostics, trend = detect_anomalies_and_series([], _make_config())
        assert len(metrics) == 0
        assert len(alerts) == 0
        assert trend == "Insufficient timestamped data"

    def test_healthy_no_alerts(self):
        """Steady low error rate should not trigger alerts."""
        events = []
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        for i in range(60):
            events.append(
                _make_event(
                    event_id=i,
                    timestamp=base + timedelta(minutes=5 * i),
                    severity="INFO",
                    message="Normal operation",
                )
            )
        metrics, alerts, diagnostics, trend = detect_anomalies_and_series(events, _make_config())
        assert len(alerts) == 0
        assert trend.startswith("Healthy") or trend in ("Stable", "Short observation window")

    def test_spike_triggers_alert(self):
        """A clear spike in errors should trigger an alert."""
        events = []
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        # 10 buckets of normal low errors
        for i in range(10):
            for _ in range(2):
                events.append(
                    _make_event(
                        event_id=len(events),
                        timestamp=base + timedelta(minutes=5 * i),
                        severity="ERROR",
                        message="Normal error",
                    )
                )
        # Spike bucket with many errors
        spike_time = base + timedelta(minutes=50)
        for _ in range(50):
            events.append(
                _make_event(
                    event_id=len(events),
                    timestamp=spike_time,
                    severity="ERROR",
                    message="Spike error",
                )
            )
        metrics, alerts, diagnostics, trend = detect_anomalies_and_series(events, _make_config())
        assert len(alerts) >= 1
        assert alerts[0].observed_count >= 25

    def test_threshold_violation(self):
        """Count above absolute threshold should trigger confirmed_threshold."""
        events = []
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        for i in range(10):
            for _ in range(2):
                events.append(
                    _make_event(
                        event_id=len(events),
                        timestamp=base + timedelta(minutes=5 * i),
                        severity="ERROR",
                        message="Error",
                    )
                )
        spike_time = base + timedelta(minutes=50)
        for _ in range(30):
            events.append(
                _make_event(
                    event_id=len(events),
                    timestamp=spike_time,
                    severity="ERROR",
                    message="Spike",
                )
            )
        config = _make_config(absolute_threshold=20, min_spike_count=10)
        metrics, alerts, diagnostics, trend = detect_anomalies_and_series(events, config)
        assert any(a.alert_type in ("confirmed_threshold", "combined") for a in alerts)

    def test_insufficient_history(self):
        """With too few buckets, should not trigger statistical alerts."""
        events = []
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        for i in range(3):
            events.append(
                _make_event(
                    event_id=i,
                    timestamp=base + timedelta(minutes=5 * i),
                    severity="ERROR",
                    message="Error",
                )
            )
        config = _make_config(min_history_buckets=10)
        metrics, alerts, diagnostics, trend = detect_anomalies_and_series(events, config)
        assert diagnostics["insufficient_history"] is True

    def test_metrics_populated(self):
        events = []
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        for i in range(10):
            events.append(
                _make_event(
                    event_id=i,
                    timestamp=base + timedelta(minutes=5 * i),
                    severity="ERROR" if i % 2 == 0 else "INFO",
                    message="Event",
                )
            )
        metrics, alerts, diagnostics, trend = detect_anomalies_and_series(events, _make_config())
        assert len(metrics) > 0
        assert all(m.total_events > 0 for m in metrics)

    def test_warning_events_tracked(self):
        events = []
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        for i in range(10):
            events.append(
                _make_event(
                    event_id=i,
                    timestamp=base + timedelta(minutes=5 * i),
                    severity="WARNING",
                    message="Warning",
                )
            )
        metrics, alerts, diagnostics, trend = detect_anomalies_and_series(events, _make_config())
        assert len(metrics) > 0
        assert all(m.warning_events > 0 for m in metrics)

    def test_invalid_timestamp_excluded(self):
        events = [
            _make_event(event_id=1, timestamp=None),
            _make_event(
                event_id=2,
                timestamp=datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
                timestamp_valid=False,
            ),
            _make_event(
                event_id=3,
                timestamp=datetime(2026, 1, 1, 12, 5, 0, tzinfo=UTC),
                timestamp_valid=True,
            ),
        ]
        metrics, alerts, diagnostics, trend = detect_anomalies_and_series(events, _make_config())
        # Only the valid timestamped event should be counted
        assert sum(m.total_events for m in metrics) == 1

    def test_alert_fields_populated(self):
        events = []
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        for i in range(10):
            for _ in range(2):
                events.append(
                    _make_event(
                        event_id=len(events),
                        timestamp=base + timedelta(minutes=5 * i),
                        severity="ERROR",
                        message="Error",
                    )
                )
        spike_time = base + timedelta(minutes=50)
        for _ in range(50):
            events.append(
                _make_event(
                    event_id=len(events),
                    timestamp=spike_time,
                    severity="ERROR",
                    message="Spike",
                )
            )
        metrics, alerts, diagnostics, trend = detect_anomalies_and_series(events, _make_config())
        if alerts:
            alert = alerts[0]
            assert alert.alert_id != ""
            assert alert.observed_count > 0
            assert alert.baseline_median >= 0
            assert alert.explanation != ""

    def test_different_time_windows(self):
        events = []
        base = datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC)
        for i in range(10):
            events.append(
                _make_event(
                    event_id=i,
                    timestamp=base + timedelta(minutes=i),
                    severity="ERROR",
                    message="Error",
                )
            )
        config = _make_config(time_window="1min", min_history_buckets=5)
        metrics, alerts, diagnostics, trend = detect_anomalies_and_series(events, config)
        assert len(metrics) >= 5
