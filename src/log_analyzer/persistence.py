"""Optional SQLite persistence for incremental file state tracking and local run history."""

from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from log_analyzer.models import AnalysisResult, FileIngestionStats


class IncrementalStateStore:
    """Manages an optional local SQLite database for incremental log processing and history."""

    def __init__(self, db_path: str | Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with closing(self._connect()) as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS processed_files (
                    file_path TEXT PRIMARY KEY,
                    file_fingerprint TEXT NOT NULL,
                    file_size INTEGER NOT NULL,
                    mtime_ns INTEGER NOT NULL,
                    parsed_events INTEGER NOT NULL,
                    malformed_lines INTEGER NOT NULL,
                    processed_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS analysis_runs (
                    run_id TEXT PRIMARY KEY,
                    generated_at TEXT NOT NULL,
                    total_files INTEGER NOT NULL,
                    total_events INTEGER NOT NULL,
                    total_errors INTEGER NOT NULL,
                    anomaly_alerts INTEGER NOT NULL,
                    trend_summary TEXT NOT NULL,
                    summary_json TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def is_file_unchanged(self, path: Path, fingerprint: str) -> bool:
        """Return True if the file path and fingerprint match an already-processed record."""
        resolved = str(path.resolve())
        with closing(self._connect()) as conn:
            row = conn.execute(
                "SELECT file_fingerprint FROM processed_files WHERE file_path = ?",
                (resolved,),
            ).fetchone()
            if row is None:
                return False
            return str(row["file_fingerprint"]) == fingerprint

    def record_processed_file(
        self, path: Path, fingerprint: str, stats: FileIngestionStats
    ) -> None:
        """Upsert processed file state after successful ingestion."""
        resolved = str(path.resolve())
        stat = path.stat()
        now_iso = datetime.now(UTC).isoformat()
        with closing(self._connect()) as conn:
            conn.execute(
                """
                INSERT INTO processed_files (
                    file_path, file_fingerprint, file_size, mtime_ns,
                    parsed_events, malformed_lines, processed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(file_path) DO UPDATE SET
                    file_fingerprint = excluded.file_fingerprint,
                    file_size = excluded.file_size,
                    mtime_ns = excluded.mtime_ns,
                    parsed_events = excluded.parsed_events,
                    malformed_lines = excluded.malformed_lines,
                    processed_at = excluded.processed_at
                """,
                (
                    resolved,
                    fingerprint,
                    stat.st_size,
                    stat.st_mtime_ns,
                    stats.parsed_events,
                    stats.malformed_lines,
                    now_iso,
                ),
            )
            conn.commit()

    def record_analysis_run(self, result: AnalysisResult) -> None:
        """Save summary metadata of an analysis run into local history."""
        summary_payload = result.to_dict().get("summary", {})
        with closing(self._connect()) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO analysis_runs (
                    run_id, generated_at, total_files, total_events,
                    total_errors, anomaly_alerts, trend_summary, summary_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    result.run_id,
                    result.generated_at.isoformat(),
                    result.total_files_scanned,
                    result.total_events_analyzed,
                    result.total_error_events,
                    len(result.anomaly_alerts),
                    result.trend_summary,
                    json.dumps(summary_payload),
                ),
            )
            conn.commit()

    def get_recent_runs(self, limit: int = 10) -> list[dict[str, Any]]:
        """Retrieve recent analysis run summaries from the SQLite database."""
        with closing(self._connect()) as conn:
            rows = conn.execute(
                """
                SELECT run_id, generated_at, total_files, total_events,
                       total_errors, anomaly_alerts, trend_summary, summary_json
                FROM analysis_runs
                ORDER BY generated_at DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            return [dict(r) for r in rows]
