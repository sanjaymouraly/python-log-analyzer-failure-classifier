"""Unit tests for file discovery, rotation ordering, and streaming."""

from __future__ import annotations

import gzip
from pathlib import Path

import pytest

from log_analyzer.discovery import (
    compute_file_fingerprint,
    discover_log_files,
    is_supported_log_file,
    stream_file_lines,
)


class TestIsSupportedLogFile:
    @pytest.mark.parametrize(
        "filename,expected",
        [
            ("app.log", True),
            ("app.txt", True),
            ("app.jsonl", True),
            ("app.out", True),
            ("app.err", True),
            ("app.log.gz", True),
            ("app.LOG", True),
            ("app.py", False),
            ("app.csv", False),
            ("log", False),
        ],
    )
    def test_extension_check(self, filename, expected):
        assert is_supported_log_file(Path(filename)) is expected


class TestDiscoverLogFiles:
    def test_discovers_files_in_directory(self, tmp_path: Path):
        (tmp_path / "a.log").write_text("line1\n", encoding="utf-8")
        (tmp_path / "b.log").write_text("line2\n", encoding="utf-8")
        (tmp_path / "c.txt").write_text("line3\n", encoding="utf-8")
        (tmp_path / "d.py").write_text("print('hi')\n", encoding="utf-8")

        files, warnings = discover_log_files([str(tmp_path)])
        names = [f.name for f in files]
        assert "a.log" in names
        assert "b.log" in names
        assert "c.txt" in names
        assert "d.py" not in names
        assert len(warnings) == 0

    def test_recursive_discovery(self, tmp_path: Path):
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "nested.log").write_text("nested\n", encoding="utf-8")
        (tmp_path / "top.log").write_text("top\n", encoding="utf-8")

        files, _ = discover_log_files([str(tmp_path)], recursive=True)
        names = [f.name for f in files]
        assert "nested.log" in names
        assert "top.log" in names

    def test_non_recursive_skips_subdirs(self, tmp_path: Path):
        subdir = tmp_path / "subdir"
        subdir.mkdir()
        (subdir / "nested.log").write_text("nested\n", encoding="utf-8")
        (tmp_path / "top.log").write_text("top\n", encoding="utf-8")

        files, _ = discover_log_files([str(tmp_path)], recursive=False)
        names = [f.name for f in files]
        assert "nested.log" not in names
        assert "top.log" in names

    def test_single_file_input(self, tmp_path: Path):
        log_file = tmp_path / "single.log"
        log_file.write_text("content\n", encoding="utf-8")

        files, warnings = discover_log_files([str(log_file)])
        assert len(files) == 1
        assert files[0].name == "single.log"

    def test_glob_pattern_input(self, tmp_path: Path):
        (tmp_path / "app1.log").write_text("a\n", encoding="utf-8")
        (tmp_path / "app2.log").write_text("b\n", encoding="utf-8")
        (tmp_path / "other.txt").write_text("c\n", encoding="utf-8")

        files, _ = discover_log_files([str(tmp_path / "app*.log")])
        names = [f.name for f in files]
        assert "app1.log" in names
        assert "app2.log" in names
        assert "other.txt" not in names

    def test_nonexistent_path_warns(self, tmp_path: Path):
        files, warnings = discover_log_files([str(tmp_path / "nonexistent")])
        assert len(files) == 0
        assert len(warnings) == 1
        assert "does not exist" in warnings[0]

    def test_rotation_ordering(self, tmp_path: Path):
        (tmp_path / "app.log.2.gz").write_text("oldest\n", encoding="utf-8")
        (tmp_path / "app.log.1").write_text("middle\n", encoding="utf-8")
        (tmp_path / "app.log").write_text("newest\n", encoding="utf-8")

        files, _ = discover_log_files([str(tmp_path)])
        names = [f.name for f in files]
        assert names.index("app.log.2.gz") < names.index("app.log.1")
        assert names.index("app.log.1") < names.index("app.log")

    def test_file_filter_regex(self, tmp_path: Path):
        (tmp_path / "app.log").write_text("a\n", encoding="utf-8")
        (tmp_path / "debug.log").write_text("b\n", encoding="utf-8")
        (tmp_path / "error.log").write_text("c\n", encoding="utf-8")

        files, _ = discover_log_files([str(tmp_path)], file_filter="error")
        names = [f.name for f in files]
        assert "error.log" in names
        assert "app.log" not in names
        assert "debug.log" not in names

    def test_multiple_inputs(self, tmp_path: Path):
        dir1 = tmp_path / "dir1"
        dir2 = tmp_path / "dir2"
        dir1.mkdir()
        dir2.mkdir()
        (dir1 / "a.log").write_text("a\n", encoding="utf-8")
        (dir2 / "b.log").write_text("b\n", encoding="utf-8")

        files, _ = discover_log_files([str(dir1), str(dir2)])
        names = [f.name for f in files]
        assert "a.log" in names
        assert "b.log" in names

    def test_deduplicates_same_file(self, tmp_path: Path):
        log_file = tmp_path / "app.log"
        log_file.write_text("content\n", encoding="utf-8")

        files, _ = discover_log_files([str(log_file), str(log_file)])
        assert len(files) == 1


class TestStreamFileLines:
    def test_streams_plain_file(self, tmp_path: Path):
        log_file = tmp_path / "test.log"
        log_file.write_text("line1\nline2\nline3\n", encoding="utf-8")

        lines = list(stream_file_lines(log_file))
        assert len(lines) == 3
        assert lines[0] == (1, "line1", False)
        assert lines[1] == (2, "line2", False)
        assert lines[2] == (3, "line3", False)

    def test_streams_gzip_file(self, tmp_path: Path):
        gz_file = tmp_path / "test.log.gz"
        with gzip.open(gz_file, "wt", encoding="utf-8") as f:
            f.write("gzline1\ngzline2\n")

        lines = list(stream_file_lines(gz_file))
        assert len(lines) == 2
        assert lines[0] == (1, "gzline1", False)
        assert lines[1] == (2, "gzline2", False)

    def test_handles_utf8_content(self, tmp_path: Path):
        log_file = tmp_path / "utf8.log"
        log_file.write_text("héllo wörld\n日本語\n", encoding="utf-8")

        lines = list(stream_file_lines(log_file))
        assert lines[0][1] == "héllo wörld"
        assert lines[1][1] == "日本語"

    def test_handles_latin1_with_encoding_param(self, tmp_path: Path):
        log_file = tmp_path / "latin1.log"
        log_file.write_bytes("café\n".encode("latin-1"))

        lines = list(stream_file_lines(log_file, encoding="latin-1"))
        assert lines[0] == (1, "café", False)

    def test_invalid_encoding_falls_back(self, tmp_path: Path):
        log_file = tmp_path / "binary.log"
        log_file.write_bytes(b"\xff\xfe\x00invalid\xffbytes\n")

        lines = list(stream_file_lines(log_file, encoding="utf-8"))
        assert len(lines) == 1
        assert lines[0][2] is True  # had_encoding_error

    def test_empty_file(self, tmp_path: Path):
        log_file = tmp_path / "empty.log"
        log_file.write_text("", encoding="utf-8")

        lines = list(stream_file_lines(log_file))
        assert len(lines) == 0

    def test_null_bytes_stripped(self, tmp_path: Path):
        log_file = tmp_path / "nulls.log"
        log_file.write_bytes(b"hello\x00world\nsecond\x00line\n")

        lines = list(stream_file_lines(log_file))
        assert len(lines) == 2
        assert lines[0][2] is True  # had_encoding_error flag
        assert "hello" in lines[0][1]
        assert "world" in lines[0][1]

    def test_file_without_trailing_newline(self, tmp_path: Path):
        log_file = tmp_path / "no_newline.log"
        log_file.write_text("last line no newline", encoding="utf-8")

        lines = list(stream_file_lines(log_file))
        assert len(lines) == 1
        assert lines[0][1] == "last line no newline"

    def test_crlf_line_endings(self, tmp_path: Path):
        log_file = tmp_path / "crlf.log"
        log_file.write_bytes(b"line1\r\nline2\r\n")

        lines = list(stream_file_lines(log_file))
        assert lines[0][1] == "line1"
        assert lines[1][1] == "line2"


class TestComputeFileFingerprint:
    def test_same_content_same_fingerprint(self, tmp_path: Path):
        f1 = tmp_path / "a.log"
        f2 = tmp_path / "b.log"
        f1.write_text("identical content\n", encoding="utf-8")
        f2.write_text("identical content\n", encoding="utf-8")
        # Set same mtime so fingerprints match
        import os
        stat = f1.stat()
        os.utime(f2, ns=(stat.st_atime_ns, stat.st_mtime_ns))

        fp1 = compute_file_fingerprint(f1)
        fp2 = compute_file_fingerprint(f2)
        assert fp1 == fp2

    def test_different_content_different_fingerprint(self, tmp_path: Path):
        f1 = tmp_path / "a.log"
        f2 = tmp_path / "b.log"
        f1.write_text("content A\n", encoding="utf-8")
        f2.write_text("content B\n", encoding="utf-8")

        fp1 = compute_file_fingerprint(f1)
        fp2 = compute_file_fingerprint(f2)
        assert fp1 != fp2

    def test_modified_file_different_fingerprint(self, tmp_path: Path):
        f1 = tmp_path / "a.log"
        f1.write_text("original\n", encoding="utf-8")
        fp1 = compute_file_fingerprint(f1)

        f1.write_text("modified\n", encoding="utf-8")
        fp2 = compute_file_fingerprint(f1)
        assert fp1 != fp2

    def test_fingerprint_is_hex_string(self, tmp_path: Path):
        f1 = tmp_path / "a.log"
        f1.write_text("test\n", encoding="utf-8")
        fp = compute_file_fingerprint(f1)
        assert len(fp) == 64
        int(fp, 16)  # Should not raise
