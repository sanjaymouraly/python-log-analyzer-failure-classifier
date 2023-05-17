"""Tests for SQLite incremental processing state and local run history."""

from __future__ import annotations

from pathlib import Path

from log_analyzer.config import AnalyzerConfig
from log_analyzer.persistence import IncrementalStateStore
from log_analyzer.pipeline import run_analysis_pipeline


def test_sqlite_incremental_processing_skips_unchanged_and_reprocesses_modified(
    tmp_path: Path, default_config: AnalyzerConfig
) -> None:
    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    f1 = logs_dir / "service_a.log"
    f2 = logs_dir / "service_b.log"

    f1.write_text(
        "2026-10-16 08:00:00,100 - svc.a - ERROR - Database connection refused\n",
        encoding="utf-8",
    )
    f2.write_text(
        "2026-10-16 08:01:00,100 - svc.b - INFO - Started worker\n",
        encoding="utf-8",
    )

    db_path = tmp_path / "state.db"

    # Run 1: Both files are new and processed
    res1, _ = run_analysis_pipeline(
        input_paths=[logs_dir],
        config=default_config,
        incremental=True,
        state_db_path=db_path,
    )
    assert res1.total_files_scanned == 2
    assert res1.total_files_skipped_incremental == 0
    assert res1.total_events_analyzed == 2

    # Run 2: Both files unchanged -> both skipped
    res2, _ = run_analysis_pipeline(
        input_paths=[logs_dir],
        config=default_config,
        incremental=True,
        state_db_path=db_path,
    )
    assert res2.total_files_scanned == 2
    assert res2.total_files_skipped_incremental == 2
    assert res2.total_events_analyzed == 0

    # Modify f2 -> only f2 should be processed on Run 3
    f2.write_text(
        "2026-10-16 08:01:00,100 - svc.b - INFO - Started worker\n"
        "2026-10-16 08:02:00,100 - svc.b - ERROR - TimeoutError: Read timed out\n",
        encoding="utf-8",
    )
    res3, _ = run_analysis_pipeline(
        input_paths=[logs_dir],
        config=default_config,
        incremental=True,
        state_db_path=db_path,
    )
    assert res3.total_files_scanned == 2
    assert res3.total_files_skipped_incremental == 1
    assert res3.total_events_analyzed == 2
    assert res3.total_error_events == 1

    store = IncrementalStateStore(db_path)
    recent_runs = store.get_recent_runs(limit=5)
    assert len(recent_runs) == 3
