"""Tests for statistical spike and threshold anomaly detection."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from log_analyzer.anomaly import detect_anomalies_and_series
from log_analyzer.config import AnomalyConfig
from log_analyzer.models import LogEvent


def _make_ts_event(event_id: int, dt: datetime, severity: str = "ERROR") -> LogEvent:
    return LogEvent(
        event_id=event_id,
        timestamp=dt,
        raw_timestamp=dt.isoformat(),
        timezone_name="UTC",
        severity=severity,
        service="payment-service",
        logger="payment.gateway",
        message="Upstream timeout",
        category_id="timeout_error",
        category_name="Timeout Errors",
        fingerprint="fp1234567890",
    )


def test_anomaly_detection_distinguishes_threshold_and_statistical_spikes() -> None:
    base = datetime(2026, 10, 16, 8, 0, 0, tzinfo=UTC)
    events: list[LogEvent] = []
    eid = 1

    # 12 five-minute windows: normal baseline has 2 errors per window
    for w in range(12):
        win_start = base + timedelta(minutes=5 * w)
        count = 2
        if w == 5:
            count = 30  # Exceeds absolute_threshold=25 AND statistical -> "combined"
        elif w == 9:
            count = 16  # Below absolute_threshold=25, but >7x baseline -> "statistical_anomaly"

        for i in range(count):
            events.append(_make_ts_event(eid, win_start + timedelta(seconds=i * 5)))
            eid += 1

    cfg = AnomalyConfig(
        time_window="5min",
        rolling_window_buckets=6,
        min_history_buckets=6,
        min_spike_count=8,
        absolute_threshold=25,
        ratio_threshold=3.0,
        mad_z_threshold=3.5,
    )

    buckets, alerts, diag, trend = detect_anomalies_and_series(events, cfg)
    assert len(buckets) == 12
    assert diag["insufficient_history"] is False
    assert len(alerts) == 2

    assert alerts[0].alert_type == "combined"
    assert alerts[0].observed_count == 30
    assert alerts[0].severity_label == "CRITICAL"

    assert alerts[1].alert_type == "statistical_anomaly"
    assert alerts[1].observed_count == 16
    assert alerts[1].severity_label == "HIGH"
    assert "spike" in trend.lower() or "worsening" in trend.lower()


def test_no_false_alerts_on_steady_baseline_or_tiny_samples() -> None:
    base = datetime(2026, 10, 16, 8, 0, 0, tzinfo=UTC)
    events: list[LogEvent] = []
    eid = 1

    # 10 windows fluctuating between 1 and 3 errors (below min_spike_count=8)
    for w in range(10):
        win_start = base + timedelta(minutes=5 * w)
        for i in range(1 + (w % 3)):
            events.append(_make_ts_event(eid, win_start + timedelta(seconds=i * 10)))
            eid += 1

    cfg = AnomalyConfig(min_spike_count=8, absolute_threshold=25)
    buckets, alerts, diag, trend = detect_anomalies_and_series(events, cfg)
    assert len(buckets) == 10
    assert len(alerts) == 0
    assert "Stable" in trend


def test_insufficient_history_suppresses_statistical_outliers_but_keeps_threshold() -> None:
    base = datetime(2026, 10, 16, 8, 0, 0, tzinfo=UTC)
    events: list[LogEvent] = []
    eid = 1

    # Only 3 windows (< min_history_buckets=6): window 0 has 1 error, window 1 has 12 errors (<25), window 2 has 28 errors (>=25)
    for w, count in enumerate([1, 12, 28]):
        win_start = base + timedelta(minutes=5 * w)
        for i in range(count):
            events.append(_make_ts_event(eid, win_start + timedelta(seconds=i * 2)))
            eid += 1

    cfg = AnomalyConfig(min_history_buckets=6, min_spike_count=8, absolute_threshold=25)
    buckets, alerts, diag, _ = detect_anomalies_and_series(events, cfg)
    assert diag["insufficient_history"] is True
    # Only the confirmed threshold violation (28 >= 25) fires; the 12-error window is suppressed due to insufficient history
    assert len(alerts) == 1
    assert alerts[0].alert_type == "confirmed_threshold"
    assert alerts[0].observed_count == 28
