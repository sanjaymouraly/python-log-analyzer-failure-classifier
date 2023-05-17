"""Performance and scale smoke test with 100,000 generated log events."""

from __future__ import annotations

import os
import time
from pathlib import Path

from log_analyzer.config import create_default_config
from log_analyzer.demo_generator import generate_scale_log_file
from log_analyzer.pipeline import run_analysis_pipeline


def _peak_rss_mb() -> float:
    """Return peak resident set size in MiB (best effort, cross-platform)."""
    try:
        import resource  # type: ignore[import-not-found]

        # ru_maxrss is KiB on Linux, bytes on macOS
        rss = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        if os.uname().sysname == "Darwin":  # type: ignore[attr-defined]
            return rss / (1024.0 * 1024.0)
        return rss / 1024.0
    except (ImportError, AttributeError):
        # Windows or unsupported: fall back to reading the process peak working set
        try:
            import ctypes

            class PROCESS_MEMORY_COUNTERS(ctypes.Structure):
                _fields_ = [
                    ("cb", ctypes.c_uint),
                    ("PageFaultCount", ctypes.c_uint),
                    ("PeakWorkingSetSize", ctypes.c_size_t),
                    ("WorkingSetSize", ctypes.c_size_t),
                    ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
                    ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
                    ("PagefileUsage", ctypes.c_size_t),
                    ("PeakPagefileUsage", ctypes.c_size_t),
                ]

            counters = PROCESS_MEMORY_COUNTERS()
            counters.cb = ctypes.sizeof(counters)
            handle = ctypes.windll.kernel32.GetCurrentProcess()
            if ctypes.windll.psapi.GetProcessMemoryInfo(
                handle, ctypes.byref(counters), counters.cb
            ):
                return counters.PeakWorkingSetSize / (1024.0 * 1024.0)
        except (AttributeError, OSError):
            pass
    return 0.0


def test_100k_events_scale_smoke_test(tmp_path: Path) -> None:
    scale_file = tmp_path / "scale_100k.log"
    event_count = 100_000

    gen_start = time.perf_counter()
    generate_scale_log_file(scale_file, event_count=event_count, seed=99)
    gen_elapsed = time.perf_counter() - gen_start
    file_size_mb = scale_file.stat().st_size / (1024 * 1024)

    cfg = create_default_config()
    cfg.deduplicate_rotated = False

    rss_before = _peak_rss_mb()
    analysis_start = time.perf_counter()
    result, _ = run_analysis_pipeline(
        input_paths=[scale_file],
        config=cfg,
    )
    analysis_elapsed = time.perf_counter() - analysis_start
    rss_after = _peak_rss_mb()

    peak_rss_mb = rss_after
    rss_delta_mb = max(0.0, rss_after - rss_before)
    throughput = event_count / max(analysis_elapsed, 0.001)

    print(
        f"\n[SCALE SMOKE TEST] Events={result.total_events_analyzed:,} | "
        f"File={file_size_mb:.2f} MB | GenTime={gen_elapsed:.2f}s | "
        f"AnalyzeTime={analysis_elapsed:.2f}s | Throughput={throughput:,.0f} ev/s | "
        f"PeakRSS={peak_rss_mb:.2f} MB (Delta={rss_delta_mb:.2f} MB)"
    )

    assert result.total_events_parsed == event_count
    assert result.total_events_analyzed == event_count
    assert result.total_error_events > 5000
    assert len(result.error_groups) == 2
    assert len(result.anomaly_alerts) >= 1
