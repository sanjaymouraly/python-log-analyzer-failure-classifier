"""Unit tests for timestamp normalization and metadata extraction."""

from __future__ import annotations

from log_analyzer.normalizer import (
    extract_error_code,
    extract_exception_type,
    extract_request_id,
    extract_source_location,
    parse_and_normalize_timestamp,
)


class TestParseAndNormalizeTimestamp:
    def test_iso8601_with_z(self):
        dt, raw, tz, valid = parse_and_normalize_timestamp("2026-01-01T12:00:00Z")
        assert dt is not None
        assert dt.tzinfo is not None
        assert valid is True
        assert dt.hour == 12

    def test_iso8601_with_offset(self):
        dt, raw, tz, valid = parse_and_normalize_timestamp("2026-01-01T12:00:00+05:30")
        assert dt is not None
        assert valid is True
        # Should be converted to UTC
        assert dt.hour == 6
        assert dt.minute == 30

    def test_iso8601_with_milliseconds(self):
        dt, raw, tz, valid = parse_and_normalize_timestamp("2026-01-01T12:00:00.123456Z")
        assert dt is not None
        assert valid is True
        assert dt.microsecond == 123456

    def test_python_logging_format(self):
        dt, raw, tz, valid = parse_and_normalize_timestamp("2026-01-01 12:00:00,123")
        assert dt is not None
        assert valid is True
        assert dt.microsecond == 123000

    def test_apache_clf_format(self):
        dt, raw, tz, valid = parse_and_normalize_timestamp("01/Jan/2026:12:00:00 +0000")
        assert dt is not None
        assert valid is True

    def test_syslog_format(self):
        dt, raw, tz, valid = parse_and_normalize_timestamp("Jan 01 12:00:00")
        assert dt is not None
        assert valid is True
        assert dt.month == 1
        assert dt.day == 1

    def test_epoch_seconds(self):
        dt, raw, tz, valid = parse_and_normalize_timestamp(1735689600)
        assert dt is not None
        assert valid is True
        assert dt.year == 2025

    def test_epoch_milliseconds(self):
        dt, raw, tz, valid = parse_and_normalize_timestamp(1735689600000)
        assert dt is not None
        assert valid is True
        assert dt.year == 2025

    def test_none_input(self):
        dt, raw, tz, valid = parse_and_normalize_timestamp(None)
        assert dt is None
        assert valid is False

    def test_invalid_string(self):
        dt, raw, tz, valid = parse_and_normalize_timestamp("not a timestamp at all")
        assert dt is None
        assert valid is False

    def test_empty_string(self):
        dt, raw, tz, valid = parse_and_normalize_timestamp("")
        assert dt is None
        assert valid is False


class TestExtractExceptionType:
    def test_from_traceback(self):
        tb = 'Traceback (most recent call last):\n  File "app.py", line 1\nValueError: bad'
        result = extract_exception_type("Something failed", traceback=tb)
        assert result == "ValueError"

    def test_from_message(self):
        result = extract_exception_type("KeyError: 'missing_key' in module")
        assert result == "KeyError"

    def test_from_explicit(self):
        result = extract_exception_type("failed", explicit_exception="RuntimeError")
        assert result == "RuntimeError"

    def test_no_exception(self):
        result = extract_exception_type("INFO: normal operation")
        assert result is None

    def test_custom_exception(self):
        result = extract_exception_type("DatabaseConnectionError: could not connect")
        assert result == "DatabaseConnectionError"


class TestExtractErrorCode:
    def test_err_underscore_format(self):
        result = extract_error_code("Failed with ERR_001")
        assert result == "ERR_001"

    def test_oracle_format(self):
        result = extract_error_code("ORA-00001: unique constraint violated")
        assert result == "ORA-00001"

    def test_http_5xx(self):
        result = extract_error_code("HTTP 503 Service Unavailable")
        assert result == "HTTP_503"

    def test_http_4xx(self):
        result = extract_error_code("HTTP 404 Not Found")
        assert result == "HTTP_404"

    def test_sqlstate(self):
        result = extract_error_code("SQLSTATE[42S02]: Base table not found")
        assert result is not None
        assert "42S02" in result

    def test_explicit_code(self):
        result = extract_error_code("failed", explicit_code="CUSTOM_42")
        assert result == "CUSTOM_42"

    def test_no_code(self):
        result = extract_error_code("normal message without codes")
        assert result is None


class TestExtractSourceLocation:
    def test_from_traceback(self):
        tb = 'Traceback:\n  File "/app/src/main.py", line 42, in handler\nValueError: bad'
        file, line = extract_source_location("failed", traceback=tb)
        assert file is not None
        assert "main.py" in file
        assert line == 42

    def test_from_message(self):
        file, line = extract_source_location("Error at app.py:99 in function")
        assert file is not None
        assert "app.py" in file
        assert line == 99

    def test_explicit_file_and_line(self):
        file, line = extract_source_location(
            "failed", explicit_file="/long/path/to/service.py", explicit_line=123
        )
        assert file is not None
        assert "service.py" in file
        assert line == 123

    def test_no_location(self):
        file, line = extract_source_location("normal message")
        assert file is None
        assert line is None


class TestExtractRequestId:
    def test_from_message_key_value(self):
        result = extract_request_id("Request failed req_id=abc123xyz")
        assert result == "abc123xyz"

    def test_from_message_bracket(self):
        result = extract_request_id("Failed [req-abc-123-def]")
        assert result == "req-abc-123-def"

    def test_explicit_request_id(self):
        result = extract_request_id("failed", explicit_request_id="explicit-req-456")
        assert result == "explicit-req-456"

    def test_from_extra_metadata(self):
        result = extract_request_id("failed", extra={"request_id": "extra-req-789"})
        assert result == "extra-req-789"

    def test_no_request_id(self):
        result = extract_request_id("normal message without ids")
        assert result is None
