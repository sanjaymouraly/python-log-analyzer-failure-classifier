"""Unit tests for SQLite-based incremental state storage."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from log_analyzer.models import AnalysisResult, FileIngestionStats
from log_analyzer.persistence import IncrementalStateStore


@pytest.fixture
def store(tmp_path: Path):
    return IncrementalStateStore(tmp_path / "state.db")


class TestIncrementalStateStore:
    def test_creates_database(self, tmp_path: Path):
        db_path = tmp_path / "new_state.db"
        IncrementalStateStore(db_path)
        assert db_path.exists()

    def test_is_file_unchanged_new_file(self, store, tmp_path: Path):
        log_file = tmp_path / "test.log"
        log_file.write_text("content\n", encoding="utf-8")
        fp = "abc123"
        assert store.is_file_unchanged(log_file, fp) is False

    def test_is_file_unchanged_after_recording(self, store, tmp_path: Path):
        log_file = tmp_path / "test.log"
        log_file.write_text("content\n", encoding="utf-8")
        fp = "abc123"
        stats = FileIngestionStats(file_path=str(log_file), total_lines=1, parsed_events=1)
        store.record_processed_file(log_file, fp, stats)
        assert store.is_file_unchanged(log_file, fp) is True

    def test_is_file_unchanged_modified_file(self, store, tmp_path: Path):
        log_file = tmp_path / "test.log"
        log_file.write_text("content\n", encoding="utf-8")
        fp = "abc123"
        stats = FileIngestionStats(file_path=str(log_file), total_lines=1, parsed_events=1)
        store.record_processed_file(log_file, fp, stats)
        # Modify the file (but fingerprint is the same string - simulates content change)
        fp2 = "def456"
        assert store.is_file_unchanged(log_file, fp2) is False

    def test_record_analysis_run(self, store):
        result = AnalysisResult(
            run_id="run-test-001",
            generated_at=datetime(2026, 1, 1, 0, 0, 0, tzinfo=UTC),
            input_paths=["/tmp/test.log"],
            config_summary={"encoding": "utf-8"},
            total_files_scanned=1,
            total_events_parsed=10,
            total_events_analyzed=10,
            total_error_events=2,
        )
        store.record_analysis_run(result)
        runs = store.get_recent_runs()
        assert len(runs) == 1
        assert runs[0]["run_id"] == "run-test-001"

    def test_get_recent_runs_limit(self, store):
        for i in range(5):
            result = AnalysisResult(
                run_id=f"run-{i}",
                generated_at=datetime(2026, 1, 1, 0, 0, i, tzinfo=UTC),
                input_paths=["/tmp/test.log"],
                config_summary={},
            )
            store.record_analysis_run(result)
        runs = store.get_recent_runs(limit=3)
        assert len(runs) == 3

    def test_get_recent_runs_empty(self, store):
        runs = store.get_recent_runs()
        assert len(runs) == 0

    def test_multiple_files_tracked(self, store, tmp_path: Path):
        for i in range(3):
            log_file = tmp_path / f"test{i}.log"
            log_file.write_text(f"content {i}\n", encoding="utf-8")
            fp = f"fp-{i}"
            stats = FileIngestionStats(file_path=str(log_file), total_lines=1, parsed_events=1)
            store.record_processed_file(log_file, fp, stats)
            assert store.is_file_unchanged(log_file, fp) is True

    def test_record_processed_file_stats(self, store, tmp_path: Path):
        log_file = tmp_path / "stats.log"
        log_file.write_text("line1\nline2\n", encoding="utf-8")
        fp = "stats-fp"
        stats = FileIngestionStats(
            file_path=str(log_file),
            total_lines=2,
            parsed_events=2,
            malformed_lines=0,
        )
        store.record_processed_file(log_file, fp, stats)
        assert store.is_file_unchanged(log_file, fp) is True
