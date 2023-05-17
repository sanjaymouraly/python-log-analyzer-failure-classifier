"""Timestamp normalization and structured metadata extraction from parsed log records."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

MONTH_MAP: dict[str, int] = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}

# ISO-8601 and Python standard logging: 2026-10-16 10:15:30,123 or 2026-10-16T10:15:30.123456+05:30
ISO_LIKE_RE = re.compile(
    r"^(?P<year>\d{4})[-/](?P<month>\d{2})[-/](?P<day>\d{2})"
    r"[T\s](?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:[.,](?P<frac>\d{1,9}))?"
    r"(?:\s*(?P<tz>Z|[+-]\d{2}:?\d{2}))?$",
    re.IGNORECASE,
)

# Apache error log timestamp: Fri Oct 16 10:15:30.123456 2026 or Oct 16 10:15:30 2026
APACHE_TS_RE = re.compile(
    r"^(?:[A-Za-z]{3}\s+)?(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\.(?P<frac>\d{1,6}))?\s+(?P<year>\d{4})$"
)

# Syslog RFC 3164 timestamp: Oct 16 10:15:30
SYSLOG_TS_RE = re.compile(
    r"^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\.(?P<frac>\d{1,6}))?$"
)

# Common Log Format: 16/Oct/2026:10:15:30 +0000
CLF_TS_RE = re.compile(
    r"^(?P<day>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<year>\d{4}):"
    r"(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"(?:\s*(?P<tz>[+-]\d{4}))?$"
)

# Python traceback final exception line: e.g. "psycopg2.OperationalError: connection refused"
TRACEBACK_EXC_RE = re.compile(
    r"^(?P<exc>(?:[A-Za-z_][A-Za-z0-9_]*\.)*[A-Za-z_][A-Za-z0-9_]*(?:Error|Exception|Warning|Fault|Exit|Interrupt|Timeout|Unavailable|Denied|Exhausted))\s*(?::|$)",
    re.MULTILINE,
)

# Inline exception class mention in message
INLINE_EXC_RE = re.compile(
    r"\b(?P<exc>(?:[A-Za-z_][A-Za-z0-9_]*\.)*(?:[A-Z][A-Za-z0-9_]*(?:Error|Exception|Timeout|Fault)|OperationalError|IntegrityError|DatabaseError|ConnectionRefusedError|ConnectionResetError|TimeoutError|ReadTimeout|ConnectTimeout|PermissionError|FileNotFoundError|AuthenticationError|AuthorizationError|MemoryError|OutOfMemoryError|ConfigurationError|ValidationError|KeyError|ValueError|TypeError|AttributeError|IndexError|ZeroDivisionError|RuntimeError|HTTPError))\b"
)

# Python traceback File ".../module.py", line 142
TRACEBACK_FILE_LINE_RE = re.compile(r'File "(?P<file>[^"]+)", line (?P<line>\d+)')

# Inline source location e.g. (app.py:42) or [worker.py:108] or file=db.py:55
INLINE_FILE_LINE_RE = re.compile(
    r"(?:[\(\[\s]|file=)(?P<file>[A-Za-z0-9_./\\-]+\.(?:py|js|ts|go|java|rb|rs|c|cpp|php)):(?P<line>\d+)(?:[\)\]\s,:]|$)"
)

# Error code extraction patterns
ERROR_CODE_PATTERNS: list[re.Pattern[str]] = [
    re.compile(r"\b(?P<code>ERR_[A-Z0-9_]{2,25})\b"),
    re.compile(r"\b(?P<code>ORA-\d{5})\b"),
    re.compile(r"\b(?P<code>AH\d{5})\b"),
    re.compile(r"\bSQLSTATE\[?(?P<code>[0-9A-Z]{5})\]?\b"),
    re.compile(
        r"\b(?P<code>E(?:CONNREFUSED|CONNRESET|TIMEDOUT|NOENT|ACCES|PERM|NOSPC|MFILE|NFILE|NOMEM|PIPE|HOSTUNREACH|NETUNREACH|ROFS))\b"
    ),
    re.compile(r"(?i)\berrno\s*[=:]?\s*(?P<code>\d+)\b"),
    re.compile(r"(?i)\berror[_-]?code\s*[=:]\s*['\"]?(?P<code>[A-Za-z0-9_-]+)['\"]?"),
    re.compile(r"\bHTTP(?:/\d\.\d)?\s+(?P<code>[45]\d{2})\b"),
    re.compile(r"(?i)\bstatus(?:_code)?\s*[=:]\s*(?P<code>[45]\d{2})\b"),
]

# Request / correlation ID extraction patterns
REQUEST_ID_PATTERNS: list[re.Pattern[str]] = [
    re.compile(
        r"(?i)\b(?:req(?:uest)?[_-]?id|corr(?:elation)?[_-]?id|trace[_-]?id|tx[_-]?id)\s*[=:]\s*['\"]?(?P<req>[A-Za-z0-9_-]{4,64})['\"]?"
    ),
    re.compile(r"\[(?P<req>(?:req|corr|trace|tx)-[A-Za-z0-9_-]{4,64})\]", re.IGNORECASE),
]


def parse_and_normalize_timestamp(
    raw_ts: str | int | float | None,
    default_year: int = 2026,
) -> tuple[datetime | None, str | None, str | None, bool]:
    """Parse a raw timestamp and normalize it to UTC.

    Returns:
        Tuple of (utc_datetime, raw_timestamp_str, timezone_name, is_valid).
    """
    if raw_ts is None:
        return None, None, None, False

    if isinstance(raw_ts, (int, float)):
        try:
            # Handle millisecond epochs if > 1e11
            ts_val = float(raw_ts) / 1000.0 if float(raw_ts) > 1e11 else float(raw_ts)
            dt = datetime.fromtimestamp(ts_val, tz=UTC)
            return dt, str(raw_ts), "UTC", True
        except (ValueError, OSError, OverflowError):
            return None, str(raw_ts), None, False

    raw_str = str(raw_ts).strip()
    if not raw_str:
        return None, None, None, False

    # 1. Try ISO-8601 / Python standard logging
    m_iso = ISO_LIKE_RE.match(raw_str)
    if m_iso:
        try:
            year = int(m_iso.group("year"))
            month = int(m_iso.group("month"))
            day = int(m_iso.group("day"))
            hour = int(m_iso.group("hour"))
            minute = int(m_iso.group("minute"))
            second = int(m_iso.group("second"))
            frac_str = m_iso.group("frac") or "0"
            microsecond = int(frac_str[:6].ljust(6, "0"))
            tz_raw = m_iso.group("tz")

            if not tz_raw or tz_raw.upper() == "Z":
                tz_label = "UTC"
                dt = datetime(year, month, day, hour, minute, second, microsecond, tzinfo=UTC)
                return dt, raw_str, tz_label, True

            tz_clean = tz_raw.replace(":", "")
            iso_candidate = (
                f"{year:04d}-{month:02d}-{day:02d}T"
                f"{hour:02d}:{minute:02d}:{second:02d}.{microsecond:06d}{tz_clean}"
            )
            dt_aware = datetime.fromisoformat(iso_candidate)
            dt_utc = dt_aware.astimezone(UTC)
            return dt_utc, raw_str, tz_raw, True
        except ValueError:
            return None, raw_str, None, False

    # 2. Try Apache timestamp
    m_apache = APACHE_TS_RE.match(raw_str)
    if m_apache:
        try:
            mon_num = MONTH_MAP.get(m_apache.group("mon").lower())
            if not mon_num:
                return None, raw_str, None, False
            frac_str = m_apache.group("frac") or "0"
            microsecond = int(frac_str[:6].ljust(6, "0"))
            dt = datetime(
                int(m_apache.group("year")),
                mon_num,
                int(m_apache.group("day")),
                int(m_apache.group("hour")),
                int(m_apache.group("minute")),
                int(m_apache.group("second")),
                microsecond,
                tzinfo=UTC,
            )
            return dt, raw_str, "UTC", True
        except ValueError:
            return None, raw_str, None, False

    # 3. Try Syslog RFC 3164 timestamp
    m_sys = SYSLOG_TS_RE.match(raw_str)
    if m_sys:
        try:
            mon_num = MONTH_MAP.get(m_sys.group("mon").lower())
            if not mon_num:
                return None, raw_str, None, False
            frac_str = m_sys.group("frac") or "0"
            microsecond = int(frac_str[:6].ljust(6, "0"))
            dt = datetime(
                default_year,
                mon_num,
                int(m_sys.group("day")),
                int(m_sys.group("hour")),
                int(m_sys.group("minute")),
                int(m_sys.group("second")),
                microsecond,
                tzinfo=UTC,
            )
            return dt, raw_str, "UTC", True
        except ValueError:
            return None, raw_str, None, False

    # 4. Try Common Log Format (CLF)
    m_clf = CLF_TS_RE.match(raw_str)
    if m_clf:
        try:
            mon_num = MONTH_MAP.get(m_clf.group("mon").lower())
            if not mon_num:
                return None, raw_str, None, False
            tz_raw = m_clf.group("tz") or "+0000"
            iso_candidate = (
                f"{int(m_clf.group('year')):04d}-{mon_num:02d}-{int(m_clf.group('day')):02d}T"
                f"{int(m_clf.group('hour')):02d}:{int(m_clf.group('minute')):02d}:{int(m_clf.group('second')):02d}{tz_raw}"
            )
            dt_aware = datetime.fromisoformat(iso_candidate)
            return dt_aware.astimezone(UTC), raw_str, tz_raw, True
        except ValueError:
            return None, raw_str, None, False

    return None, raw_str, None, False


def extract_exception_type(
    message: str,
    traceback: str | None = None,
    explicit_exception: str | None = None,
) -> str | None:
    """Extract the most specific exception class name from traceback or message."""
    if explicit_exception:
        cleaned = explicit_exception.strip()
        if cleaned:
            # If full traceback was passed in explicit_exception, extract class from last line
            matches = list(TRACEBACK_EXC_RE.finditer(cleaned))
            if matches:
                return matches[-1].group("exc")
            inline = INLINE_EXC_RE.search(cleaned)
            if inline:
                return inline.group("exc")
            if len(cleaned) < 80 and " " not in cleaned:
                return cleaned

    if traceback:
        matches = list(TRACEBACK_EXC_RE.finditer(traceback))
        if matches:
            return matches[-1].group("exc")

    m_inline = INLINE_EXC_RE.search(message)
    if m_inline:
        return m_inline.group("exc")

    return None


def extract_error_code(
    message: str,
    traceback: str | None = None,
    explicit_code: str | int | None = None,
) -> str | None:
    """Extract error code or HTTP status code from event fields or message text."""
    if explicit_code is not None and str(explicit_code).strip():
        return str(explicit_code).strip()

    combined = f"{message}\n{traceback}" if traceback else message
    for pattern in ERROR_CODE_PATTERNS:
        match = pattern.search(combined)
        if match:
            code = match.group("code")
            if code.isdigit() and 400 <= int(code) <= 599:
                return f"HTTP_{code}"
            return code
    return None


def extract_source_location(
    message: str,
    traceback: str | None = None,
    explicit_file: str | None = None,
    explicit_line: int | str | None = None,
) -> tuple[str | None, int | None]:
    """Extract source code filename and line number from metadata, traceback, or message."""
    src_file: str | None = (
        explicit_file.strip() if explicit_file and str(explicit_file).strip() else None
    )
    src_line: int | None = None
    if explicit_line is not None:
        try:
            src_line = int(explicit_line)
        except (ValueError, TypeError):
            src_line = None

    if src_file and src_line is not None:
        return _clean_source_filename(src_file), src_line

    if traceback:
        tb_matches = list(TRACEBACK_FILE_LINE_RE.finditer(traceback))
        if tb_matches:
            last_frame = tb_matches[-1]
            return _clean_source_filename(last_frame.group("file")), int(last_frame.group("line"))

    m_inline = INLINE_FILE_LINE_RE.search(message)
    if m_inline:
        return _clean_source_filename(m_inline.group("file")), int(m_inline.group("line"))

    return (_clean_source_filename(src_file) if src_file else None), src_line


def _clean_source_filename(raw_path: str) -> str:
    """Normalize a source file path to a clean relative or basename representation."""
    normalized = raw_path.replace("\\", "/").strip()
    parts = [p for p in normalized.split("/") if p]
    if len(parts) >= 2:
        return "/".join(parts[-2:])
    return normalized


def extract_request_id(
    message: str,
    explicit_request_id: str | None = None,
    extra: dict[str, Any] | None = None,
) -> str | None:
    """Extract request, correlation, or trace ID from fields or message."""
    if explicit_request_id and str(explicit_request_id).strip():
        return str(explicit_request_id).strip()

    if extra:
        for key in ("request_id", "req_id", "correlation_id", "corr_id", "trace_id", "tx_id"):
            val = extra.get(key)
            if val and str(val).strip():
                return str(val).strip()

    for pattern in REQUEST_ID_PATTERNS:
        m = pattern.search(message)
        if m:
            return m.group("req")

    return None
