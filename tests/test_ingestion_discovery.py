"""Tests for file discovery, rotated log ordering, gzip streaming, and encoding edge cases."""

from __future__ import annotations

import gzip
from pathlib import Path

from log_analyzer.config import AnalyzerConfig
from log_analyzer.discovery import discover_log_files, stream_file_lines
from log_analyzer.pipeline import run_analysis_pipeline


def test_rotated_log_ordering_and_glob_discovery(tmp_path: Path) -> None:
    (tmp_path / "app.log").write_text("line3\n", encoding="utf-8")
    (tmp_path / "app.log.1").write_text("line2\n", encoding="utf-8")
    with gzip.open(tmp_path / "app.log.2.gz", "wt", encoding="utf-8") as gz:
        gz.write("line1\n")

    sub = tmp_path / "subdir with spaces"
    sub.mkdir()
    (sub / "service (prod).log").write_text("line4\n", encoding="utf-8")

    # Recursive discovery orders .log.2.gz -> .log.1 -> .log
    files, warns = discover_log_files([tmp_path], recursive=True)
    assert not warns
    names = [f.name for f in files]
    assert names.index("app.log.2.gz") < names.index("app.log.1") < names.index("app.log")
    assert "service (prod).log" in names

    # Non-recursive excludes subdir
    files_non_rec, _ = discover_log_files([tmp_path], recursive=False)
    assert "service (prod).log" not in [f.name for f in files_non_rec]

    # Glob discovery
    glob_files, _ = discover_log_files([str(tmp_path / "*.gz")], recursive=False)
    assert len(glob_files) == 1
    assert glob_files[0].name == "app.log.2.gz"

    # File filter and non-matching glob warning
    filtered_files, _ = discover_log_files([tmp_path], recursive=True, file_filter=r"^service")
    assert [f.name for f in filtered_files] == ["service (prod).log"]

    no_match_files, warns2 = discover_log_files([str(tmp_path / "*.nomatch")])
    assert len(no_match_files) == 0
    assert any("No files matched glob pattern" in w for w in warns2)


def test_encoding_fallback_and_empty_files(tmp_path: Path, default_config: AnalyzerConfig) -> None:
    empty_file = tmp_path / "empty.log"
    empty_file.write_text("", encoding="utf-8")

    # File containing invalid UTF-8 byte sequence (0xff 0xfe) and null bytes
    corrupt_utf8 = tmp_path / "corrupt_utf8.log"
    raw_bytes = (
        b"2026-10-16 10:00:00,000 - auth.svc - ERROR - Invalid byte sequence: \x00\xff\xfe in payload\n"
        b"2026-10-16 10:00:05,000 - auth.svc - INFO - Subsequent valid line\n"
    )
    corrupt_utf8.write_bytes(raw_bytes)

    lines = list(stream_file_lines(corrupt_utf8, encoding="utf-8"))
    assert len(lines) == 2
    assert lines[0][2] is True  # had_encoding_error == True
    assert lines[1][2] is False

    result, _ = run_analysis_pipeline(
        input_paths=[empty_file, corrupt_utf8],
        config=default_config,
    )
    assert result.total_files_scanned == 2
    assert result.total_events_analyzed == 2
    assert result.total_error_events == 1
    corrupt_stats = [f for f in result.file_stats if "corrupt_utf8" in f.file_path][0]
    assert corrupt_stats.encoding_errors == 1
