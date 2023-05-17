"""Tests for timestamp normalization, metadata extraction, and multiline traceback assembly."""

from __future__ import annotations

from datetime import UTC
from pathlib import Path

from log_analyzer.discovery import stream_file_lines
from log_analyzer.normalizer import (
    extract_error_code,
    extract_exception_type,
    extract_request_id,
    extract_source_location,
    parse_and_normalize_timestamp,
)
from log_analyzer.parsers import parse_file_stream
from log_analyzer.security import SecretRedactor


def test_timestamp_normalization_across_timezones() -> None:
    # IST (+05:30) -> UTC
    dt1, raw1, tz1, ok1 = parse_and_normalize_timestamp("2026-10-16T15:30:00+05:30")
    assert ok1 is True
    assert dt1 is not None
    assert dt1.tzinfo == UTC
    assert dt1.hour == 10
    assert dt1.minute == 0
    assert tz1 == "+05:30"
    assert raw1 == "2026-10-16T15:30:00+05:30"

    # EDT (-04:00) -> UTC
    dt2, _, tz2, ok2 = parse_and_normalize_timestamp("2026-10-16T06:00:00.500-04:00")
    assert ok2 is True
    assert dt2 is not None
    assert dt2.hour == 10
    assert dt2.microsecond == 500000
    assert tz2 == "-04:00"

    # Apache timestamp
    dt3, _, _, ok3 = parse_and_normalize_timestamp("Fri Oct 16 10:15:30.123456 2026")
    assert ok3 is True
    assert dt3 is not None
    assert (dt3.year, dt3.month, dt3.day, dt3.hour) == (2026, 10, 16, 10)

    # CLF timestamp
    dt4, _, _, ok4 = parse_and_normalize_timestamp("16/Oct/2026:10:15:30 +0000")
    assert ok4 is True
    assert dt4 is not None
    assert dt4.hour == 10

    # Unix epoch seconds & milliseconds
    dt5, _, _, ok5 = parse_and_normalize_timestamp(1792145730)
    assert ok5 is True
    assert dt5 is not None

    dt6, _, _, ok6 = parse_and_normalize_timestamp(1792145730123)
    assert ok6 is True
    assert dt6 is not None

    # Invalid timestamps
    dt_bad, _, _, ok_bad = parse_and_normalize_timestamp("2026-99-99 99:99:99")
    assert ok_bad is False
    assert dt_bad is None

    dt_none, _, _, ok_none = parse_and_normalize_timestamp(None)
    assert ok_none is False
    assert dt_none is None


def test_multiline_traceback_grouped_as_single_event(
    tmp_path: Path, default_redactor: SecretRedactor
) -> None:
    log_content = """2026-10-16 09:00:01,100 - order.service - INFO - [req-1001] Starting order checkout
2026-10-16 09:00:02,250 - order.service - ERROR - [req-1001] Failed to process order
Traceback (most recent call last):
  File "/app/src/order/views.py", line 52, in checkout
    charge_customer(order_id)
  File "/app/src/order/billing.py", line 119, in charge_customer
    raise ValueError("Invalid currency code")
ValueError: Invalid currency code
During handling of the above exception, another exception occurred:
Traceback (most recent call last):
  File "/app/src/order/middleware.py", line 88, in handle_request
    return view(request)
  File "/app/src/order/views.py", line 56, in checkout
    raise RuntimeError("Checkout pipeline aborted")
RuntimeError: Checkout pipeline aborted
2026-10-16 09:00:03,000 - order.service - INFO - [req-1002] Next request started
"""
    f = tmp_path / "multiline.log"
    f.write_text(log_content, encoding="utf-8")

    events = []
    final_stats = None
    for ev, err, stats in parse_file_stream(
        stream_file_lines(f), file_path=f, redactor=default_redactor
    ):
        final_stats = stats
        assert err is None
        if ev:
            events.append(ev)

    assert len(events) == 3
    assert final_stats is not None
    assert final_stats.multiline_events == 1

    err_event = events[1]
    assert err_event.severity == "ERROR"
    assert err_event.request_id == "req-1001"
    assert err_event.traceback is not None
    assert "During handling of the above exception" in err_event.traceback
    # Innermost / final exception is RuntimeError at views.py:56
    assert err_event.exception_type == "RuntimeError"
    assert err_event.source_file == "order/views.py"
    assert err_event.source_line == 56


def test_metadata_extraction_helpers() -> None:
    assert (
        extract_exception_type("Database error", "psycopg2.OperationalError: deadlock")
        == "psycopg2.OperationalError"
    )
    assert extract_error_code("Failed with SQLSTATE[08006] on replica") == "08006"
    assert extract_error_code("Upstream returned HTTP 503 Service Unavailable") == "HTTP_503"
    assert extract_error_code("Oracle failure ORA-12154 encountered") == "ORA-12154"
    assert extract_request_id("Operation failed for correlation_id=corr-abc-999") == "corr-abc-999"
    src_f, src_l = extract_source_location("Error in (worker/tasks.py:304) during sync")
    assert src_f == "worker/tasks.py"
    assert src_l == 304
