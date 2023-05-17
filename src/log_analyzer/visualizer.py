"""Matplotlib chart generation for log analysis reports."""

from __future__ import annotations

import base64
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt

from log_analyzer.models import AnalysisResult

PALETTE = {
    "DEBUG": "#64748b",
    "INFO": "#0ea5e9",
    "WARNING": "#f59e0b",
    "ERROR": "#ef4444",
    "CRITICAL": "#7f1d1d",
    "UNKNOWN": "#94a3b8",
    "primary": "#1e293b",
    "accent": "#2563eb",
    "baseline": "#0d9488",
    "threshold": "#dc2626",
    "spike": "#b91c1c",
    "bg": "#ffffff",
    "grid": "#e2e8f0",
}


def _apply_chart_style(ax: plt.Axes, title: str, xlabel: str = "", ylabel: str = "") -> None:
    ax.set_facecolor(PALETTE["bg"])
    ax.set_title(title, fontsize=13, fontweight="bold", color="#0f172a", pad=12, loc="left")
    if xlabel:
        ax.set_xlabel(xlabel, fontsize=10, color="#334155", labelpad=8)
    if ylabel:
        ax.set_ylabel(ylabel, fontsize=10, color="#334155", labelpad=8)
    ax.grid(True, linestyle="--", alpha=0.6, color=PALETTE["grid"])
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_color("#cbd5e1")
    ax.spines["bottom"].set_color("#cbd5e1")
    ax.tick_params(colors="#334155", labelsize=9)


def _save_and_encode(fig: plt.Figure, out_path: Path) -> str:
    """Save figure to PNG file and return base64 data URI for standalone HTML embedding."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(str(out_path), dpi=140, bbox_inches="tight", facecolor="#ffffff")
    plt.close(fig)
    raw_bytes = out_path.read_bytes()
    b64 = base64.b64encode(raw_bytes).decode("ascii")
    return f"data:image/png;base64,{b64}"


def generate_all_charts(
    result: AnalysisResult, output_dir: str | Path
) -> dict[str, tuple[Path, str]]:
    """Generate all 6 required analytical PNG charts.

    Returns:
        Dictionary mapping chart key to (saved Path, base64 data URI string).
    """
    charts_dir = Path(output_dir) / "charts"
    charts_dir.mkdir(parents=True, exist_ok=True)

    generated: dict[str, tuple[Path, str]] = {}

    # 1. Errors Over Time
    p1 = charts_dir / "errors_over_time.png"
    generated["errors_over_time"] = (p1, _plot_errors_over_time(result, p1))

    # 2. Severity Distribution
    p2 = charts_dir / "severity_distribution.png"
    generated["severity_distribution"] = (p2, _plot_severity_distribution(result, p2))

    # 3. Top Recurring Failures
    p3 = charts_dir / "top_recurring_failures.png"
    generated["top_recurring_failures"] = (p3, _plot_top_recurring_failures(result, p3))

    # 4. Failure Categories
    p4 = charts_dir / "failure_categories.png"
    generated["failure_categories"] = (p4, _plot_failure_categories(result, p4))

    # 5. Errors by Service
    p5 = charts_dir / "errors_by_service.png"
    generated["errors_by_service"] = (p5, _plot_errors_by_service(result, p5))

    # 6. Detected Anomaly Spikes
    p6 = charts_dir / "anomaly_spikes.png"
    generated["anomaly_spikes"] = (p6, _plot_anomaly_spikes(result, p6))

    return generated


def _plot_errors_over_time(result: AnalysisResult, out_path: Path) -> str:
    fig, ax = plt.subplots(figsize=(10, 4.2))
    buckets = result.time_series_buckets

    if not buckets:
        _apply_chart_style(ax, "Errors & Warnings Over Time (No Timestamped Data)")
        ax.text(
            0.5,
            0.5,
            "No timestamped log events available for time-series visualization",
            ha="center",
            va="center",
            transform=ax.transAxes,
            color="#64748b",
            fontsize=11,
        )
        return _save_and_encode(fig, out_path)

    times = [float(mdates.date2num(b.window_start)) for b in buckets]
    errors = [b.error_events for b in buckets]
    warnings = [b.warning_events for b in buckets]
    totals = [b.total_events for b in buckets]

    ax.plot(
        times,
        totals,
        label="Total Events",
        color="#94a3b8",
        linewidth=1.3,
        linestyle=":",
        alpha=0.8,
    )
    ax.plot(
        times,
        warnings,
        label="Warnings",
        color=PALETTE["WARNING"],
        linewidth=1.8,
        marker="o",
        markersize=3,
    )
    ax.plot(
        times,
        errors,
        label="Errors / Critical",
        color=PALETTE["ERROR"],
        linewidth=2.3,
        marker="o",
        markersize=4,
    )
    ax.fill_between(times, errors, color=PALETTE["ERROR"], alpha=0.12)

    win_str = result.anomaly_diagnostics.get("time_window", "5min")
    _apply_chart_style(
        ax,
        f"Log Activity & Failure Volume Over Time ({win_str} windows)",
        xlabel="Timestamp (UTC)",
        ylabel="Event Count",
    )
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M\n%b %d"))
    ax.legend(frameon=True, facecolor="#f8fafc", edgecolor="#e2e8f0", fontsize=9)
    fig.tight_layout()
    return _save_and_encode(fig, out_path)


def _plot_severity_distribution(result: AnalysisResult, out_path: Path) -> str:
    fig, ax = plt.subplots(figsize=(8, 4.2))
    order = ["CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "UNKNOWN"]
    counts = [result.severity_counts.get(s, 0) for s in order]
    non_zero = [(s, c) for s, c in zip(order, counts, strict=True) if c > 0]

    if not non_zero:
        non_zero = [("INFO", 0)]

    labels = [x[0] for x in non_zero][::-1]
    values = [x[1] for x in non_zero][::-1]
    colors = [PALETTE.get(lbl, "#64748b") for lbl in labels]

    bars = ax.barh(labels, values, color=colors, height=0.58, edgecolor="#ffffff")
    total = max(sum(values), 1)
    max_val = max(values) if values else 1

    for bar, val in zip(bars, values, strict=True):
        pct = (val / total) * 100.0
        ax.text(
            val + max_val * 0.015,
            bar.get_y() + bar.get_height() / 2,
            f"{val:,} ({pct:.1f}%)",
            va="center",
            ha="left",
            fontsize=9,
            fontweight="bold",
            color="#1e293b",
        )

    ax.set_xlim(0, max_val * 1.22 if max_val > 0 else 10)
    _apply_chart_style(
        ax,
        "Log Event Severity Distribution",
        xlabel="Number of Log Events",
        ylabel="Severity Level",
    )
    fig.tight_layout()
    return _save_and_encode(fig, out_path)


def _plot_top_recurring_failures(result: AnalysisResult, out_path: Path) -> str:
    fig, ax = plt.subplots(figsize=(10, 4.8))
    groups = result.error_groups[:10]

    if not groups:
        _apply_chart_style(ax, "Top Recurring Failure Fingerprints (Zero Failures Detected)")
        ax.text(
            0.5,
            0.5,
            "No recurring error groups found in analyzed logs",
            ha="center",
            va="center",
            transform=ax.transAxes,
            color="#64748b",
            fontsize=11,
        )
        return _save_and_encode(fig, out_path)

    labels = []
    values = []
    for grp in reversed(groups):
        short_tmpl = grp.template[:48] + ("..." if len(grp.template) > 48 else "")
        labels.append(f"[{grp.fingerprint[:8]}] {short_tmpl}")
        values.append(grp.count)

    bars = ax.barh(labels, values, color="#2563eb", height=0.6, alpha=0.9)
    max_val = max(values) if values else 1
    for bar, val in zip(bars, values, strict=True):
        ax.text(
            val + max_val * 0.015,
            bar.get_y() + bar.get_height() / 2,
            f"{val:,}",
            va="center",
            ha="left",
            fontsize=9,
            fontweight="bold",
            color="#1e293b",
        )

    ax.set_xlim(0, max_val * 1.18 if max_val > 0 else 10)
    _apply_chart_style(
        ax,
        "Top Recurring Failure Fingerprints (Masked Templates)",
        xlabel="Occurrence Count",
    )
    fig.tight_layout()
    return _save_and_encode(fig, out_path)


def _plot_failure_categories(result: AnalysisResult, out_path: Path) -> str:
    fig, ax = plt.subplots(figsize=(9, 4.5))
    cat_items = [
        (cat, cnt)
        for cat, cnt in result.category_counts.items()
        if cat != "Normal Operation" and cnt > 0
    ]
    cat_items.sort(key=lambda kv: kv[1])

    if not cat_items:
        _apply_chart_style(ax, "Failure Categories Breakdown (No Failures Classified)")
        ax.text(
            0.5,
            0.5,
            "Zero failure categories recorded",
            ha="center",
            va="center",
            transform=ax.transAxes,
            color="#64748b",
            fontsize=11,
        )
        return _save_and_encode(fig, out_path)

    labels = [x[0] for x in cat_items]
    values = [x[1] for x in cat_items]
    cat_colors = [
        "#dc2626",
        "#ea580c",
        "#d97706",
        "#7c3aed",
        "#2563eb",
        "#0891b2",
        "#059669",
        "#4f46e5",
        "#be123c",
        "#475569",
    ]
    bar_colors = [cat_colors[i % len(cat_colors)] for i in range(len(labels))]

    bars = ax.barh(labels, values, color=bar_colors, height=0.6)
    total_cat = max(sum(values), 1)
    max_val = max(values) if values else 1

    for bar, val in zip(bars, values, strict=True):
        pct = (val / total_cat) * 100.0
        ax.text(
            val + max_val * 0.015,
            bar.get_y() + bar.get_height() / 2,
            f"{val:,} ({pct:.1f}%)",
            va="center",
            ha="left",
            fontsize=9,
            fontweight="bold",
            color="#1e293b",
        )

    ax.set_xlim(0, max_val * 1.22 if max_val > 0 else 10)
    _apply_chart_style(
        ax,
        "Classified Failure Categories",
        xlabel="Classified Failure Events",
    )
    fig.tight_layout()
    return _save_and_encode(fig, out_path)


def _plot_errors_by_service(result: AnalysisResult, out_path: Path) -> str:
    fig, ax = plt.subplots(figsize=(9, 4.5))
    services = sorted(
        result.service_counts.keys(),
        key=lambda s: (result.service_error_counts.get(s, 0), result.service_counts.get(s, 0)),
        reverse=True,
    )[:10]

    if not services:
        _apply_chart_style(ax, "Events & Errors by Application Service (No Data)")
        return _save_and_encode(fig, out_path)

    services_rev = list(reversed(services))
    err_vals = [result.service_error_counts.get(s, 0) for s in services_rev]
    non_err_vals = [
        max(0, result.service_counts.get(s, 0) - result.service_error_counts.get(s, 0))
        for s in services_rev
    ]

    ax.barh(
        services_rev, non_err_vals, label="Normal / Warning Events", color="#94a3b8", height=0.58
    )
    ax.barh(
        services_rev,
        err_vals,
        left=non_err_vals,
        label="Error / Critical Events",
        color="#ef4444",
        height=0.58,
    )

    max_tot = max((a + b for a, b in zip(non_err_vals, err_vals, strict=True)), default=1)
    for idx, (ne, er) in enumerate(zip(non_err_vals, err_vals, strict=True)):
        tot = ne + er
        ax.text(
            tot + max_tot * 0.015,
            idx,
            f"{er:,} err / {tot:,} total",
            va="center",
            ha="left",
            fontsize=8.5,
            fontweight="bold",
            color="#1e293b",
        )

    ax.set_xlim(0, max_tot * 1.26 if max_tot > 0 else 10)
    _apply_chart_style(
        ax,
        "Log Volume & Failure Concentration by Service",
        xlabel="Event Count",
        ylabel="Service / Component",
    )
    ax.legend(frameon=True, facecolor="#f8fafc", edgecolor="#e2e8f0", fontsize=9)
    fig.tight_layout()
    return _save_and_encode(fig, out_path)


def _plot_anomaly_spikes(result: AnalysisResult, out_path: Path) -> str:
    fig, ax = plt.subplots(figsize=(10, 4.4))
    buckets = result.time_series_buckets

    if not buckets:
        _apply_chart_style(ax, "Statistical Anomaly & Spike Detection (No Timestamped Data)")
        ax.text(
            0.5,
            0.5,
            "No timestamped log events available for spike analysis",
            ha="center",
            va="center",
            transform=ax.transAxes,
            color="#64748b",
            fontsize=11,
        )
        return _save_and_encode(fig, out_path)

    times = [float(mdates.date2num(b.window_start)) for b in buckets]
    errors = [b.error_events for b in buckets]
    baselines = [b.rolling_baseline for b in buckets]
    threshold = result.anomaly_diagnostics.get("absolute_threshold", 25)

    ax.plot(
        times,
        errors,
        label="Observed Errors / Window",
        color="#1e293b",
        linewidth=2.0,
        marker="o",
        markersize=3.5,
    )
    ax.plot(
        times,
        baselines,
        label="Rolling Baseline Mean",
        color=PALETTE["baseline"],
        linewidth=1.8,
        linestyle="--",
    )
    ax.axhline(
        y=threshold,
        color=PALETTE["threshold"],
        linestyle="-.",
        linewidth=1.4,
        alpha=0.8,
        label=f"Confirmed Alert Threshold ({threshold})",
    )

    spike_times = [float(mdates.date2num(b.window_start)) for b in buckets if b.is_anomaly]
    spike_counts = [b.error_events for b in buckets if b.is_anomaly]
    if spike_times:
        ax.scatter(
            spike_times,
            spike_counts,
            color="#dc2626",
            s=95,
            zorder=5,
            edgecolors="#7f1d1d",
            linewidths=1.5,
            label=f"Detected Anomaly Spikes ({len(spike_times)})",
        )
        for st, sc in zip(spike_times[:5], spike_counts[:5], strict=True):
            ax.annotate(
                f"SPIKE: {sc}",
                xy=(st, sc),
                xytext=(0, 8),
                textcoords="offset points",
                ha="center",
                fontsize=8.5,
                fontweight="bold",
                color="#b91c1c",
            )

    max_y = max(max(errors, default=1), threshold)
    ax.set_ylim(0, max_y * 1.25 if max_y > 0 else 10)
    win_str = result.anomaly_diagnostics.get("time_window", "5min")
    _apply_chart_style(
        ax,
        f"Anomaly & Spike Detection ({win_str} windows — Rolling Baseline & Thresholds)",
        xlabel="Timestamp (UTC)",
        ylabel="Errors per Window",
    )
    ax.xaxis.set_major_formatter(mdates.DateFormatter("%H:%M\n%b %d"))
    ax.legend(
        frameon=True, facecolor="#f8fafc", edgecolor="#e2e8f0", fontsize=8.5, loc="upper left"
    )
    fig.tight_layout()
    return _save_and_encode(fig, out_path)
