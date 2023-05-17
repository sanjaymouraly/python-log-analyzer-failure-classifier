"""Unit tests for multi-format log parsers and format detection."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from log_analyzer.config import create_default_config
from log_analyzer.parsers import (
    detect_file_format,
    detect_line_format,
    is_multiline_continuation,
    parse_file_stream,
    parse_single_header_line,
)
from log_analyzer.security import SecretRedactor


@pytest.fixture
def redactor():
    return SecretRedactor(create_default_config().security)


class TestDetectLineFormat:
    def test_python_logging_format(self):
        line = "2026-01-01 12:00:00,123 ERROR [myapp.module] Something failed"
        assert detect_line_format(line) == "python"

    def test_iso_format(self):
        line = "2026-01-01T12:00:00.123Z ERROR myapp Something failed"
        assert detect_line_format(line) == "iso"

    def test_jsonl_format(self):
        line = '{"timestamp": "2026-01-01T12:00:00Z", "level": "ERROR", "message": "failed"}'
        assert detect_line_format(line) == "jsonl"

    def test_nginx_format(self):
        line = "2026/01/01 12:00:00 [error] 1234#0: *1 connect() failed"
        assert detect_line_format(line) == "nginx"

    def test_apache_format(self):
        line = "[Mon Jan 01 12:00:00.000000 2026] [core:error] [pid 1234] failed"
        assert detect_line_format(line) == "apache"

    def test_syslog_format(self):
        line = "Jan 01 12:00:00 myhost myapp[1234]: ERROR something failed"
        assert detect_line_format(line) == "syslog"

    def test_unknown_format(self):
        line = "just some random text without any structure"
        assert detect_line_format(line) is None

    def test_custom_format(self):
        custom_re = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2})\s+(?P<sev>\w+)\s+(?P<msg>.*)$")
        line = "2026-01-01 ERROR custom message"
        assert detect_line_format(line, custom_re=custom_re) == "custom"


class TestDetectFileFormat:
    def test_dominant_python_format(self):
        lines = [
            "2026-01-01 12:00:00,000 INFO [app] started",
            "2026-01-01 12:00:01,000 ERROR [app] failed",
            "2026-01-01 12:00:02,000 INFO [app] recovered",
        ]
        assert detect_file_format(lines) == "python"

    def test_dominant_jsonl_format(self):
        lines = [
            '{"timestamp": "2026-01-01T12:00:00Z", "level": "INFO", "message": "started"}',
            '{"timestamp": "2026-01-01T12:00:01Z", "level": "ERROR", "message": "failed"}',
        ]
        assert detect_file_format(lines) == "jsonl"

    def test_mixed_format(self):
        lines = [
            "2026-01-01 12:00:00,000 INFO [app] started",
            '{"timestamp": "2026-01-01T12:00:01Z", "level": "ERROR", "message": "failed"}',
            "random text",
            "more random text",
        ]
        result = detect_file_format(lines)
        assert "mixed" in result

    def test_unknown_format(self):
        lines = ["random text", "more random text"]
        assert detect_file_format(lines) == "unknown"

    def test_empty_input(self):
        assert detect_file_format([]) == "unknown"


class TestParseSingleHeaderLine:
    def test_python_format(self):
        line = "2026-01-01 12:00:00,123 ERROR [myapp.module] Something failed"
        result = parse_single_header_line(line, 1)
        assert result is not None
        assert result.parser_format == "python"
        assert result.severity == "ERROR"
        assert "Something failed" in result.message

    def test_iso_format(self):
        line = "2026-01-01T12:00:00.123Z ERROR myapp Something failed"
        result = parse_single_header_line(line, 1)
        assert result is not None
        assert result.parser_format == "iso"
        assert result.severity == "ERROR"

    def test_jsonl_format(self):
        line = '{"timestamp": "2026-01-01T12:00:00Z", "level": "ERROR", "message": "failed", "service": "api"}'
        result = parse_single_header_line(line, 1)
        assert result is not None
        assert result.parser_format == "jsonl"
        assert result.severity == "ERROR"
        assert result.service == "api"

    def test_nginx_format(self):
        line = "2026/01/01 12:00:00 [error] 1234#0: *1 connect() failed"
        result = parse_single_header_line(line, 1)
        assert result is not None
        assert result.parser_format == "nginx"
        assert result.severity == "ERROR"

    def test_apache_format(self):
        line = "[Mon Jan 01 12:00:00.000000 2026] [core:error] [pid 1234] failed"
        result = parse_single_header_line(line, 1)
        assert result is not None
        assert result.parser_format == "apache"

    def test_syslog_format(self):
        line = "Jan 01 12:00:00 myhost myapp[1234]: ERROR something failed"
        result = parse_single_header_line(line, 1)
        assert result is not None
        assert result.parser_format == "syslog"

    def test_none_for_unparseable(self):
        line = "completely unparseable garbage without any structure"
        result = parse_single_header_line(line, 1)
        assert result is None

    def test_custom_format(self):
        custom_re = re.compile(r"^(?P<timestamp>\d{4}-\d{2}-\d{2})\s+(?P<severity>\w+)\s+(?P<message>.*)$")
        line = "2026-01-01 ERROR custom message"
        result = parse_single_header_line(line, 1, custom_re=custom_re)
        assert result is not None
        assert result.parser_format == "custom"
        assert result.severity == "ERROR"

    def test_preferred_format_python(self):
        line = "2026-01-01 12:00:00,123 ERROR [app] message"
        result = parse_single_header_line(line, 1, preferred_format="python")
        assert result is not None
        assert result.parser_format == "python"

    def test_preferred_format_iso(self):
        line = "2026-01-01T12:00:00.123Z ERROR app message"
        result = parse_single_header_line(line, 1, preferred_format="iso")
        assert result is not None
        assert result.parser_format == "iso"

    def test_preferred_format_jsonl(self):
        line = '{"timestamp": "2026-01-01T12:00:00Z", "level": "ERROR", "message": "failed"}'
        result = parse_single_header_line(line, 1, preferred_format="jsonl")
        assert result is not None
        assert result.parser_format == "jsonl"

    def test_empty_line_returns_none(self):
        result = parse_single_header_line("", 1)
        assert result is None

    def test_whitespace_only_returns_none(self):
        result = parse_single_header_line("   ", 1)
        assert result is None


class TestIsMultilineContinuation:
    def _make_active(self):
        from log_analyzer.parsers import RawParsedFields
        return RawParsedFields(
            parser_format="python",
            raw_timestamp=None,
            severity="ERROR",
            service="app",
            logger="test",
            message="test",
            traceback_lines=[],
            explicit_exception=None,
            explicit_error_code=None,
            explicit_file=None,
            explicit_line=None,
            explicit_request_id=None,
            extra_metadata={},
        )

    def test_traceback_start_is_continuation(self):
        line = "Traceback (most recent call last):"
        active = self._make_active()
        assert is_multiline_continuation(line, active) is True

    def test_traceback_frame_is_continuation(self):
        line = '  File "/app/main.py", line 42, in handler'
        active = self._make_active()
        assert is_multiline_continuation(line, active) is True

    def test_exception_line_in_traceback(self):
        line = "ValueError: invalid input"
        active = self._make_active()
        active.in_traceback_block = True
        assert is_multiline_continuation(line, active) is True

    def test_indented_continuation(self):
        line = "    indented continuation text"
        active = self._make_active()
        assert is_multiline_continuation(line, active) is True

    def test_normal_line_not_continuation(self):
        line = "2026-01-01 12:00:00,000 INFO [app] normal message"
        active = self._make_active()
        assert is_multiline_continuation(line, active) is False

    def test_none_active_returns_false(self):
        line = "Traceback (most recent call last):"
        assert is_multiline_continuation(line, None) is False

    def test_jsonl_format_returns_false(self):
        line = "Traceback (most recent call last):"
        active = self._make_active()
        active.parser_format = "jsonl"
        assert is_multiline_continuation(line, active) is False


class TestParseFileStream:
    def test_parses_python_format_file(self, tmp_path: Path, redactor):
        log_file = tmp_path / "test.log"
        log_file.write_text(
            "2026-01-01 12:00:00,000 INFO [app] started\n"
            "2026-01-01 12:00:01,000 ERROR [app] connection failed\n"
            "2026-01-01 12:00:02,000 INFO [app] recovered\n",
            encoding="utf-8",
        )

        lines = [(i + 1, line, False) for i, line in enumerate(log_file.read_text().splitlines())]
        events = []
        errors = []
        for ev, err, _stats in parse_file_stream(iter(lines), log_file, redactor):
            if ev:
                events.append(ev)
            if err:
                errors.append(err)

        assert len(events) == 3
        assert len(errors) == 0
        assert events[0].severity == "INFO"
        assert events[1].severity == "ERROR"
        assert events[1].message == "connection failed"

    def test_parses_jsonl_file(self, tmp_path: Path, redactor):
        log_file = tmp_path / "test.jsonl"
        log_file.write_text(
            '{"timestamp": "2026-01-01T12:00:00Z", "level": "INFO", "message": "started", "service": "api"}\n'
            '{"timestamp": "2026-01-01T12:00:01Z", "level": "ERROR", "message": "failed", "service": "api"}\n',
            encoding="utf-8",
        )

        lines = [(i + 1, line, False) for i, line in enumerate(log_file.read_text().splitlines())]
        events = []
        for ev, _err, _stats in parse_file_stream(iter(lines), log_file, redactor):
            if ev:
                events.append(ev)

        assert len(events) == 2
        assert events[0].service == "api"
        assert events[1].severity == "ERROR"

    def test_handles_multiline_traceback(self, tmp_path: Path, redactor):
        log_file = tmp_path / "traceback.log"
        log_file.write_text(
            "2026-01-01 12:00:00,000 ERROR [app] Something failed\n"
            "Traceback (most recent call last):\n"
            '  File "/app/main.py", line 42, in handler\n'
            "ValueError: invalid input\n",
            encoding="utf-8",
        )

        lines = [(i + 1, line, False) for i, line in enumerate(log_file.read_text().splitlines())]
        events = []
        for ev, _err, _stats in parse_file_stream(iter(lines), log_file, redactor):
            if ev:
                events.append(ev)

        assert len(events) == 1
        assert events[0].exception_type == "ValueError"
        assert "Traceback" in (events[0].traceback or "")

    def test_handles_malformed_lines(self, tmp_path: Path, redactor):
        log_file = tmp_path / "mixed.log"
        log_file.write_text(
            "2026-01-01 12:00:00,000 INFO [app] good line\n"
            "this is not a valid log line at all\n"
            "2026-01-01 12:00:01,000 ERROR [app] another good line\n",
            encoding="utf-8",
        )

        lines = [(i + 1, line, False) for i, line in enumerate(log_file.read_text().splitlines())]
        events = []
        errors = []
        for ev, err, _stats in parse_file_stream(iter(lines), log_file, redactor):
            if ev:
                events.append(ev)
            if err:
                errors.append(err)

        assert len(events) == 2
        assert len(errors) == 1

    def test_empty_file(self, tmp_path: Path, redactor):
        log_file = tmp_path / "empty.log"
        log_file.write_text("", encoding="utf-8")

        lines = []
        events = []
        errors = []
        for ev, err, _stats in parse_file_stream(iter(lines), log_file, redactor):
            if ev:
                events.append(ev)
            if err:
                errors.append(err)

        assert len(events) == 0
        assert len(errors) == 0

    def test_stats_tracking(self, tmp_path: Path, redactor):
        log_file = tmp_path / "stats.log"
        log_file.write_text(
            "2026-01-01 12:00:00,000 INFO [app] line 1\n"
            "2026-01-01 12:00:01,000 ERROR [app] line 2\n",
            encoding="utf-8",
        )

        lines = [(i + 1, line, False) for i, line in enumerate(log_file.read_text().splitlines())]
        all_stats = []
        for _ev, _err, stats in parse_file_stream(iter(lines), log_file, redactor):
            all_stats.append(stats)

        final_stats = all_stats[-1]
        assert final_stats.total_lines == 2
        assert final_stats.parsed_events == 2

    def test_event_ids_increment(self, tmp_path: Path, redactor):
        log_file = tmp_path / "ids.log"
        log_file.write_text(
            "2026-01-01 12:00:00,000 INFO [app] line 1\n"
            "2026-01-01 12:00:01,000 INFO [app] line 2\n",
            encoding="utf-8",
        )

        lines = [(i + 1, line, False) for i, line in enumerate(log_file.read_text().splitlines())]
        events = []
        for ev, _err, _stats in parse_file_stream(iter(lines), log_file, redactor, start_event_id=10):
            if ev:
                events.append(ev)

        assert events[0].event_id == 10
        assert events[1].event_id == 11
