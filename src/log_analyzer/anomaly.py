"""Statistical spike and threshold anomaly detection using pandas."""

from __future__ import annotations

from collections import Counter
from datetime import timedelta
from typing import Any

import numpy as np
import pandas as pd

from log_analyzer.config import AnomalyConfig
from log_analyzer.models import (
    AnomalyAlert,
    LogEvent,
    TimeBucketMetric,
    severity_rank,
)

PANDAS_FREQ_MAP: dict[str, str] = {
    "1min": "1min",
    "5min": "5min",
    "15min": "15min",
    "1h": "1h",
    "1d": "1D",
}

WINDOW_TIMEDELTA_MAP: dict[str, timedelta] = {
    "1min": timedelta(minutes=1),
    "5min": timedelta(minutes=5),
    "15min": timedelta(minutes=15),
    "1h": timedelta(hours=1),
    "1d": timedelta(days=1),
}


def detect_anomalies_and_series(
    events: list[LogEvent],
    config: AnomalyConfig,
    failure_severity: str = "ERROR",
) -> tuple[list[TimeBucketMetric], list[AnomalyAlert], dict[str, Any], str]:
    """Aggregate events into time buckets using pandas and detect error spikes/anomalies.

    Returns:
        Tuple of:
        - list of TimeBucketMetric across the continuous timeline
        - list of AnomalyAlert objects
        - anomaly_diagnostics dictionary
        - trend_summary string
    """
    freq = PANDAS_FREQ_MAP.get(config.time_window, "5min")
    win_delta = WINDOW_TIMEDELTA_MAP.get(config.time_window, timedelta(minutes=5))
    min_fail_rank = severity_rank(failure_severity)
    warn_rank = severity_rank("WARNING")

    timestamped = [e for e in events if e.timestamp is not None and e.timestamp_valid]
    if not timestamped:
        diagnostics = {
            "status": "no_timestamped_events",
            "time_window": config.time_window,
            "total_buckets": 0,
            "insufficient_history": True,
            "note": "No events with valid timestamps were available for time-series analysis.",
        }
        return [], [], diagnostics, "Insufficient timestamped data"

    # Build records for pandas DataFrame
    rows = []
    bucket_failure_events: dict[pd.Timestamp, list[LogEvent]] = {}
    for ev in timestamped:
        if ev.timestamp is None:
            continue
        ev_rank = severity_rank(ev.severity)
        is_err = 1 if ev_rank >= min_fail_rank else 0
        is_warn = 1 if ev_rank == warn_rank else 0
        rows.append(
            {
                "timestamp": ev.timestamp,
                "total": 1,
                "error": is_err,
                "warning": is_warn,
            }
        )
        if is_err:
            floored = pd.Timestamp(ev.timestamp).floor(freq)
            bucket_failure_events.setdefault(floored, []).append(ev)

    df = pd.DataFrame(rows)
    df["bucket"] = pd.to_datetime(df["timestamp"], utc=True).dt.floor(freq)

    grouped = df.groupby("bucket")[["total", "error", "warning"]].sum().sort_index()

    # Reindex to include missing periods (zero-event windows) between start and end
    full_index = pd.date_range(
        start=grouped.index.min(),
        end=grouped.index.max(),
        freq=freq,
        tz="UTC",
    )
    grouped = grouped.reindex(full_index, fill_value=0)

    total_buckets = len(grouped)
    insufficient_history = total_buckets < config.min_history_buckets

    error_series = grouped["error"].astype(float)

    # Compute global robust statistics (Median and MAD) excluding top extreme outliers if history allows
    global_median = float(np.median(error_series.values))
    abs_dev = np.abs(error_series.values - global_median)
    global_mad = float(np.median(abs_dev))
    sorted_dev = np.sort(abs_dev)
    trim_idx = max(1, int(len(sorted_dev) * 0.8))
    trimmed_mean_ad = float(np.mean(sorted_dev[:trim_idx]))
    global_mean = float(np.mean(error_series.values))

    # Rolling baseline (using prior windows shifted by 1 to avoid self-contamination of spikes)
    rolling_win = max(2, config.rolling_window_buckets)
    shifted = error_series.shift(1)
    rolling_median = (
        shifted.rolling(window=rolling_win, min_periods=1).median().fillna(global_median)
    )
    rolling_mean = shifted.rolling(window=rolling_win, min_periods=1).mean().fillna(global_mean)

    # Effective MAD denominator to handle zero-baseline or constant-baseline logs gracefully
    effective_mad = max(global_mad, trimmed_mean_ad * 0.8, 1.0)

    alerts: list[AnomalyAlert] = []
    bucket_metrics: list[TimeBucketMetric] = []
    alert_counter = 1

    for bucket_ts, row in grouped.iterrows():
        win_start = bucket_ts.to_pydatetime()
        win_end = win_start + win_delta
        err_count = int(row["error"])
        warn_count = int(row["warning"])
        tot_count = int(row["total"])

        local_base_mean = float(rolling_mean.loc[bucket_ts])
        local_base_med = float(rolling_median.loc[bucket_ts])

        # Reference baseline for ratio calculation (guard against 0 baseline using max(..., 1.0))
        ref_baseline = max(local_base_med, global_median, 1.0)
        ratio = err_count / ref_baseline
        pct_increase = ((err_count - ref_baseline) / ref_baseline) * 100.0

        # Modified Z-score using robust median and effective MAD
        diff_from_med = max(0.0, float(err_count) - max(local_base_med, global_median))
        mod_z = (0.6745 * diff_from_med) / effective_mad

        # Check rules ONLY if minimum spike count is met (prevents tiny sample false positives)
        is_threshold_violation = (
            err_count >= config.min_spike_count and err_count >= config.absolute_threshold
        )
        is_statistical_spike = (
            not insufficient_history
            and err_count >= config.min_spike_count
            and mod_z >= config.mad_z_threshold
            and ratio >= config.ratio_threshold
        )

        alert_type: str | None = None
        if is_threshold_violation and is_statistical_spike:
            alert_type = "combined"
        elif is_threshold_violation:
            alert_type = "confirmed_threshold"
        elif is_statistical_spike:
            alert_type = "statistical_anomaly"

        bucket_metrics.append(
            TimeBucketMetric(
                window_start=win_start,
                total_events=tot_count,
                error_events=err_count,
                warning_events=warn_count,
                rolling_baseline=local_base_mean,
                is_anomaly=alert_type is not None,
                alert_type=alert_type,
            )
        )

        if alert_type is not None:
            win_events = bucket_failure_events.get(bucket_ts, [])
            top_cat = ""
            top_srv = ""
            top_fp = ""
            sample_msg = ""
            if win_events:
                top_cat = Counter(e.category_name for e in win_events).most_common(1)[0][0]
                top_srv = Counter(e.service for e in win_events).most_common(1)[0][0]
                top_fp = Counter(e.fingerprint for e in win_events).most_common(1)[0][0]
                sample_msg = win_events[0].message[:200]

            reasons: list[str] = []
            if is_threshold_violation:
                reasons.append(
                    f"Confirmed threshold violation: {err_count} errors >= threshold of {config.absolute_threshold} per {config.time_window}"
                )
            if is_statistical_spike:
                reasons.append(
                    f"Statistical anomaly indicator: {err_count} errors is {ratio:.1f}x baseline "
                    f"(+{pct_increase:.0f}% over baseline median {local_base_med:.1f}, modified Z-score={mod_z:.2f} >= {config.mad_z_threshold})"
                )

            sev_label = (
                "CRITICAL"
                if (alert_type == "combined" or err_count >= config.absolute_threshold * 1.5)
                else "HIGH"
            )

            alerts.append(
                AnomalyAlert(
                    alert_id=f"ALERT-{alert_counter:03d}",
                    window_start=win_start,
                    window_end=win_end,
                    window_size=config.time_window,
                    alert_type=alert_type,
                    severity_label=sev_label,
                    observed_count=err_count,
                    baseline_mean=local_base_mean,
                    baseline_median=local_base_med,
                    baseline_mad=global_mad,
                    ratio_over_baseline=ratio,
                    modified_z_score=mod_z,
                    threshold_limit=config.absolute_threshold,
                    explanation="; ".join(reasons) + f". Primary driver: {top_cat} in '{top_srv}'.",
                    top_category=top_cat,
                    top_service=top_srv,
                    top_fingerprint=top_fp,
                    sample_message=sample_msg,
                )
            )
            alert_counter += 1

    # Compute trend summary
    trend_summary = _compute_trend_summary(error_series, alerts, insufficient_history)

    diagnostics = {
        "status": "analyzed",
        "time_window": config.time_window,
        "total_buckets": total_buckets,
        "min_history_buckets": config.min_history_buckets,
        "insufficient_history": insufficient_history,
        "global_mean_errors_per_bucket": round(global_mean, 3),
        "global_median_errors_per_bucket": round(global_median, 3),
        "global_mad_errors_per_bucket": round(global_mad, 3),
        "absolute_threshold": config.absolute_threshold,
        "ratio_threshold": config.ratio_threshold,
        "mad_z_threshold": config.mad_z_threshold,
        "min_spike_count": config.min_spike_count,
        "note": (
            f"History has only {total_buckets} buckets (< {config.min_history_buckets} required); "
            "statistical anomaly indicators are suppressed to prevent small-sample false positives."
            if insufficient_history
            else f"Evaluated {total_buckets} continuous {config.time_window} windows using rolling baselines and Median/MAD outlier detection."
        ),
    }

    return bucket_metrics, alerts, diagnostics, trend_summary


def _compute_trend_summary(
    error_series: pd.Series,
    alerts: list[AnomalyAlert],
    insufficient_history: bool,
) -> str:
    """Summarize whether the error rate is worsening, improving, spiking, or stable."""
    total_errors = int(error_series.sum())
    if total_errors == 0:
        return "Healthy — Zero error events recorded across the analyzed period."
    if insufficient_history or len(error_series) < 4:
        if alerts:
            return f"Threshold Alert Active — {len(alerts)} window(s) exceeded configured error threshold."
        return "Short observation window — Insufficient history for multi-period trend comparison."

    mid = len(error_series) // 2
    first_half_mean = float(error_series.iloc[:mid].mean())
    second_half_mean = float(error_series.iloc[mid:].mean())

    if second_half_mean > max(first_half_mean * 1.5, 2.0):
        return (
            f"Worsening — Error rate increased from {first_half_mean:.1f}/window in the first half "
            f"to {second_half_mean:.1f}/window in the second half ({len(alerts)} anomaly window(s) detected)."
        )
    if first_half_mean > max(second_half_mean * 1.5, 2.0):
        return (
            f"Improving / Recovering — Error rate decreased from {first_half_mean:.1f}/window in the first half "
            f"to {second_half_mean:.1f}/window in the second half ({len(alerts)} historical spike window(s))."
        )
    if alerts:
        return (
            f"Intermittent Spikes — Baseline is stable ({error_series.median():.1f}/window median), "
            f"but {len(alerts)} acute anomaly spike window(s) occurred."
        )
    return f"Stable — Error rate remained within normal bounds (median {error_series.median():.1f}/window, no anomaly spikes)."
