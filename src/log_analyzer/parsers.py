"""Multi-format log parsers, automatic format detection, and multiline traceback assembly."""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from log_analyzer.models import (
    FileIngestionStats,
    LogEvent,
    ParseErrorRecord,
    normalize_severity,
)
from log_analyzer.normalizer import (
    extract_error_code,
    extract_exception_type,
    extract_request_id,
    extract_source_location,
    parse_and_normalize_timestamp,
)
from log_analyzer.security import SecretRedactor

# 1. Python Standard Logging:
# Examples:
# 2026-10-16 10:15:30,123 - app.db - ERROR - [req-123] (db.py:45) Connection failed
# 2026-10-16 10:15:30,123 ERROR [app.db] (db.py:45) - Connection failed
PYTHON_LOG_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2},\d{3,6})\s+"
    r"(?:-\s+(?P<logger1>[A-Za-z0-9_.:-]+)\s+-\s+(?P<severity1>[A-Za-z]+)\s+-\s+|"
    r"\[?(?P<severity2>[A-Za-z]+)\]?\s+\[?(?P<logger2>[A-Za-z0-9_.:-]+)\]?\s+(?:(?P<module2>[A-Za-z0-9_.-]+:\d+)\s+)?(?:-\s+)?)"
    r"(?P<message>.*)$"
)

# Python basicConfig without timestamp: ERROR:app.worker:Something failed
PYTHON_BASIC_NO_TS_RE = re.compile(
    r"^(?P<severity>DEBUG|INFO|WARNING|WARN|ERROR|CRITICAL|FATAL):(?P<logger>[A-Za-z0-9_.-]+):(?P<message>.+)$"
)

# 2. ISO-8601 Application Log:
# Examples:
# 2026-10-16T10:15:30.123Z [ERROR] [payment-service] (gateway.py:88) [req-99] Message
# 2026-10-16 10:15:30.123+00:00 ERROR payment-service: Message
ISO_LOG_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?:\[(?P<severity1>CRITICAL|CRIT|FATAL|EMERGENCY|EMERG|ALERT|SEVERE|ERROR|ERR|WARNING|WARN|NOTICE|INFO|DEBUG|DBG|TRACE)\]|"
    r"(?P<severity2>CRITICAL|CRIT|FATAL|EMERGENCY|EMERG|ALERT|SEVERE|ERROR|ERR|WARNING|WARN|NOTICE|INFO|DEBUG|DBG|TRACE)\b)\s*"
    r"(?:\[(?P<service>[A-Za-z0-9_.-]+)\]\s*)?"
    r"(?:\[(?P<logger>[A-Za-z0-9_.:-]+)\]\s*)?"
    r"(?:(?P<service_colon>[A-Za-z0-9_.-]+):\s+)?"
    r"(?:-\s+|:\s+)?"
    r"(?P<message>.*)$",
    re.IGNORECASE,
)

# 3. Nginx Error Log:
# Example: 2026/10/16 10:15:30 [error] 1234#1234: *5678 connect() failed...
NGINX_ERR_RE = re.compile(
    r"^(?P<timestamp>\d{4}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"\[(?P<severity>[a-zA-Z]+)\]\s+"
    r"(?P<pid>\d+)#(?P<tid>\d+):\s+"
    r"(?:\*(?P<cid>\d+)\s+)?"
    r"(?P<message>.*)$"
)

# 4. Apache Error Log:
# Example: [Fri Oct 16 10:15:30.123456 2026] [core:error] [pid 1234:tid 5678] [client 10.0.0.1:54321] AH00124: ...
APACHE_ERR_RE = re.compile(
    r"^\[(?P<timestamp>(?:[A-Za-z]{3}\s+)?[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?\s+\d{4})\]\s+"
    r"\[(?:(?P<module>[A-Za-z0-9_.-]+):)?(?P<severity>[A-Za-z]+)\]\s+"
    r"(?:\[pid\s+(?P<pid>[^\]]+)\]\s+)?"
    r"(?:\[client\s+(?P<client>[^\]]+)\]\s+)?"
    r"(?P<message>.*)$"
)

# 5. Syslog RFC 5424 & RFC 3164:
# RFC 5424: <165>1 2026-10-16T10:15:30.000Z host app 1234 ID47 - Message
SYSLOG_5424_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?1\s+"
    r"(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+"
    r"(?P<host>[A-Za-z0-9_.-]+)\s+"
    r"(?P<service>[A-Za-z0-9_./-]+)\s+"
    r"(?P<pid>[A-Za-z0-9_-]+)\s+"
    r"(?P<msgid>[A-Za-z0-9_-]+)\s+"
    r"(?P<sd>-|\[.*?\])\s+"
    r"(?P<message>.*)$"
)

# RFC 3164: <34>Oct 16 10:15:30 host app[1234]: Message
SYSLOG_3164_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?"
    r"(?P<timestamp>[A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>[A-Za-z0-9_.-]+)\s+"
    r"(?P<service>[A-Za-z0-9_./-]+)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.*)$"
)

# Key-value pairs inside structured text messages: service=payment component=db
KV_SERVICE_RE = re.compile(r"\b(?:service|app)=([A-Za-z0-9_.-]+)")
KV_COMPONENT_RE = re.compile(r"\b(?:component|module|logger)=([A-Za-z0-9_.:-]+)")
BRACKET_SEVERITY_RE = re.compile(
    r"^\[(?P<sev>DEBUG|INFO|WARNING|WARN|ERROR|ERR|CRITICAL|CRIT|FATAL)\]\s*(?P<rest>.*)$",
    re.IGNORECASE,
)

# Multiline traceback / continuation detection patterns
TRACEBACK_START_RE = re.compile(
    r"^(?:Traceback \(most recent call last\):|"
    r"During handling of the above exception, another exception occurred:|"
    r"The above exception was the direct cause of the following exception:|"
    r"Caused by:)"
)
TRACEBACK_FRAME_RE = re.compile(
    r"^\s+(?:File\s+\".*\", line \d+|at\s+[A-Za-z0-9_$./<>]+\(|[\^~]+\s*$|\.\.\.\s+\d+\s+more)"
)
TRACEBACK_EXC_LINE_RE = re.compile(
    r"^(?:[A-Za-z_][A-Za-z0-9_]*\.)*[A-Za-z_][A-Za-z0-9_]*(?:Error|Exception|Warning|Fault|Exit|Interrupt|Timeout|Unavailable|Denied|Exhausted)(?:\s*:.*|\s*)$"
)

SYSLOG_PRI_SEVERITY: dict[int, str] = {
    0: "CRITICAL",
    1: "CRITICAL",
    2: "CRITICAL",
    3: "ERROR",
    4: "WARNING",
    5: "INFO",
    6: "INFO",
    7: "DEBUG",
}


@dataclass
class RawParsedFields:
    """Intermediate parsed fields before full normalization and classification."""

    parser_format: str
    raw_timestamp: str | int | float | None
    severity: str
    service: str
    logger: str
    message: str
    traceback_lines: list[str] = field(default_factory=list)
    explicit_exception: str | None = None
    explicit_error_code: str | int | None = None
    explicit_file: str | None = None
    explicit_line: int | str | None = None
    explicit_request_id: str | None = None
    extra_metadata: dict[str, Any] = field(default_factory=dict)
    log_line_number: int = 1
    in_traceback_block: bool = False


def detect_line_format(line: str, custom_re: re.Pattern[str] | None = None) -> str | None:
    """Detect the format of a single log line."""
    stripped = line.strip()
    if not stripped:
        return None
    if stripped.startswith("{") and stripped.endswith("}"):
        return "jsonl"
    if PYTHON_LOG_RE.match(line) or PYTHON_BASIC_NO_TS_RE.match(line):
        return "python"
    if NGINX_ERR_RE.match(line):
        return "nginx"
    if APACHE_ERR_RE.match(line):
        return "apache"
    if SYSLOG_5424_RE.match(line) or SYSLOG_3164_RE.match(line):
        return "syslog"
    if ISO_LOG_RE.match(line):
        return "iso"
    if custom_re and custom_re.match(line):
        return "custom"
    return None


def detect_file_format(
    sample_lines: Iterable[str], custom_re: re.Pattern[str] | None = None
) -> str:
    """Inspect a sample of initial lines to determine the primary format of a file."""
    counts: dict[str, int] = {}
    for line in sample_lines:
        fmt = detect_line_format(line, custom_re=custom_re)
        if fmt:
            counts[fmt] = counts.get(fmt, 0) + 1
    if not counts:
        return "unknown"
    if len(counts) > 1:
        # Check if one format dominates (>80%), otherwise mark as mixed
        total = sum(counts.values())
        top_fmt, top_count = max(counts.items(), key=lambda kv: kv[1])
        if top_count / total >= 0.85:
            return top_fmt
        return f"mixed({','.join(sorted(counts.keys()))})"
    return next(iter(counts.keys()))


def _parse_json_line(line: str, line_num: int, default_service: str) -> RawParsedFields | None:
    try:
        payload = json.loads(line)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None

    raw_ts = (
        payload.get("timestamp")
        or payload.get("time")
        or payload.get("ts")
        or payload.get("@timestamp")
        or payload.get("datetime")
    )
    raw_sev = (
        payload.get("level")
        or payload.get("severity")
        or payload.get("lvl")
        or payload.get("log.level")
        or "INFO"
    )
    service = str(
        payload.get("service")
        or payload.get("app")
        or payload.get("application")
        or payload.get("service.name")
        or default_service
    )
    logger = str(
        payload.get("logger")
        or payload.get("module")
        or payload.get("component")
        or payload.get("name")
        or service
    )
    message = str(
        payload.get("message")
        or payload.get("msg")
        or payload.get("event")
        or payload.get("error")
        or ""
    )
    tb = (
        payload.get("traceback")
        or payload.get("stack_trace")
        or payload.get("exc_info")
        or payload.get("stack")
    )
    tb_lines = str(tb).splitlines() if tb else []

    known_keys = {
        "timestamp",
        "time",
        "ts",
        "@timestamp",
        "datetime",
        "level",
        "severity",
        "lvl",
        "log.level",
        "service",
        "app",
        "application",
        "service.name",
        "logger",
        "module",
        "component",
        "name",
        "message",
        "msg",
        "event",
        "traceback",
        "stack_trace",
        "exc_info",
        "stack",
        "exception",
        "exception_type",
        "error_code",
        "code",
        "status_code",
        "file",
        "filename",
        "source_file",
        "line",
        "lineno",
        "source_line",
        "request_id",
        "req_id",
        "correlation_id",
        "corr_id",
        "trace_id",
    }
    extra = {k: v for k, v in payload.items() if k not in known_keys}

    return RawParsedFields(
        parser_format="jsonl",
        raw_timestamp=raw_ts,
        severity=normalize_severity(str(raw_sev), default="UNKNOWN"),
        service=service,
        logger=logger,
        message=message,
        traceback_lines=tb_lines,
        explicit_exception=payload.get("exception") or payload.get("exception_type"),
        explicit_error_code=(
            payload.get("error_code") or payload.get("code") or payload.get("status_code")
        ),
        explicit_file=(
            payload.get("file") or payload.get("filename") or payload.get("source_file")
        ),
        explicit_line=(payload.get("line") or payload.get("lineno") or payload.get("source_line")),
        explicit_request_id=(
            payload.get("request_id")
            or payload.get("req_id")
            or payload.get("correlation_id")
            or payload.get("corr_id")
            or payload.get("trace_id")
        ),
        extra_metadata=extra,
        log_line_number=line_num,
    )


def _parse_python_line(line: str, line_num: int, default_service: str) -> RawParsedFields | None:
    m = PYTHON_LOG_RE.match(line)
    if m:
        logger_raw = m.group("logger1") or m.group("logger2") or default_service
        mod2_raw = m.group("module2")
        sev_raw = m.group("severity1") or m.group("severity2") or "INFO"
        msg = m.group("message")
        src_file: str | None = None
        src_line: int | None = None
        target_mod = mod2_raw or logger_raw
        # Check if target_mod is module:line (e.g. processor:142)
        if ":" in target_mod:
            parts = target_mod.rsplit(":", 1)
            if parts[1].isdigit():
                if not mod2_raw:
                    logger_raw = parts[0]
                src_file = f"{parts[0].split('.')[-1]}.py"
                src_line = int(parts[1])
        service = logger_raw.split(".")[0] if "." in logger_raw else logger_raw
        return RawParsedFields(
            parser_format="python",
            raw_timestamp=m.group("timestamp"),
            severity=normalize_severity(sev_raw),
            service=service,
            logger=logger_raw,
            message=msg,
            explicit_file=src_file,
            explicit_line=src_line,
            log_line_number=line_num,
        )

    m_no_ts = PYTHON_BASIC_NO_TS_RE.match(line)
    if m_no_ts:
        logger_raw = m_no_ts.group("logger")
        service = logger_raw.split(".")[0] if "." in logger_raw else logger_raw
        return RawParsedFields(
            parser_format="python",
            raw_timestamp=None,
            severity=normalize_severity(m_no_ts.group("severity")),
            service=service,
            logger=logger_raw,
            message=m_no_ts.group("message"),
            log_line_number=line_num,
        )
    return None


def _parse_iso_line(line: str, line_num: int, default_service: str) -> RawParsedFields | None:
    m = ISO_LOG_RE.match(line)
    if not m:
        return None
    msg = m.group("message")
    sev_raw = m.group("severity1") or m.group("severity2") or "INFO"
    service = m.group("service") or m.group("service_colon") or ""
    logger = m.group("logger") or ""

    if not service:
        kv_srv = KV_SERVICE_RE.search(msg)
        service = kv_srv.group(1) if kv_srv else default_service
    if not logger:
        kv_comp = KV_COMPONENT_RE.search(msg)
        logger = kv_comp.group(1) if kv_comp else service

    return RawParsedFields(
        parser_format="iso",
        raw_timestamp=m.group("timestamp"),
        severity=normalize_severity(sev_raw),
        service=service,
        logger=logger,
        message=msg,
        log_line_number=line_num,
    )


def _parse_syslog_line(line: str, line_num: int, default_service: str) -> RawParsedFields | None:
    m5424 = SYSLOG_5424_RE.match(line)
    if m5424:
        pri_str = m5424.group("pri")
        sev = "INFO"
        if pri_str is not None:
            sev = SYSLOG_PRI_SEVERITY.get(int(pri_str) % 8, "INFO")
        msg = m5424.group("message")
        b_match = BRACKET_SEVERITY_RE.match(msg)
        if b_match:
            sev = normalize_severity(b_match.group("sev"), default=sev)
            msg = b_match.group("rest")
        service = m5424.group("service") or default_service
        return RawParsedFields(
            parser_format="syslog",
            raw_timestamp=m5424.group("timestamp"),
            severity=sev,
            service=service,
            logger=f"{m5424.group('host')}.{service}",
            message=msg,
            extra_metadata={"host": m5424.group("host"), "pid": m5424.group("pid")},
            log_line_number=line_num,
        )

    m3164 = SYSLOG_3164_RE.match(line)
    if m3164:
        pri_str = m3164.group("pri")
        sev = "INFO"
        if pri_str is not None:
            sev = SYSLOG_PRI_SEVERITY.get(int(pri_str) % 8, "INFO")
        msg = m3164.group("message")
        b_match = BRACKET_SEVERITY_RE.match(msg)
        if b_match:
            sev = normalize_severity(b_match.group("sev"), default=sev)
            msg = b_match.group("rest")
        elif re.search(r"(?i)\b(?:error|failed|failure|denied|refused|critical|fatal)\b", msg):
            if sev == "INFO" and pri_str is None:
                sev = "ERROR"
        service = m3164.group("service") or default_service
        return RawParsedFields(
            parser_format="syslog",
            raw_timestamp=m3164.group("timestamp"),
            severity=sev,
            service=service,
            logger=f"{m3164.group('host')}.{service}",
            message=msg,
            extra_metadata={"host": m3164.group("host"), "pid": m3164.group("pid")},
            log_line_number=line_num,
        )
    return None


def _parse_apache_line(line: str, line_num: int, default_service: str) -> RawParsedFields | None:
    m = APACHE_ERR_RE.match(line)
    if not m:
        return None
    module = m.group("module") or "apache"
    sev = normalize_severity(m.group("severity"), default="ERROR")
    return RawParsedFields(
        parser_format="apache",
        raw_timestamp=m.group("timestamp"),
        severity=sev,
        service=default_service if default_service != "unknown" else "apache-httpd",
        logger=f"apache.{module}",
        message=m.group("message"),
        extra_metadata={"pid": m.group("pid"), "client": m.group("client")},
        log_line_number=line_num,
    )


def _parse_nginx_line(line: str, line_num: int, default_service: str) -> RawParsedFields | None:
    m = NGINX_ERR_RE.match(line)
    if not m:
        return None
    sev = normalize_severity(m.group("severity"), default="ERROR")
    return RawParsedFields(
        parser_format="nginx",
        raw_timestamp=m.group("timestamp"),
        severity=sev,
        service=default_service if default_service != "unknown" else "nginx-gateway",
        logger="nginx.error",
        message=m.group("message"),
        extra_metadata={"pid": m.group("pid"), "tid": m.group("tid"), "cid": m.group("cid")},
        log_line_number=line_num,
    )


def _parse_custom_line(
    line: str,
    line_num: int,
    default_service: str,
    custom_re: re.Pattern[str] | None,
) -> RawParsedFields | None:
    if not custom_re:
        return None
    m = custom_re.match(line)
    if not m:
        return None
    groups = m.groupdict()
    service = groups.get("service") or default_service
    logger = groups.get("logger") or service
    sev = normalize_severity(groups.get("severity"), default="INFO")
    return RawParsedFields(
        parser_format="custom",
        raw_timestamp=groups.get("timestamp"),
        severity=sev,
        service=service,
        logger=logger,
        message=groups.get("message") or "",
        explicit_exception=groups.get("exception_type"),
        explicit_error_code=groups.get("error_code"),
        explicit_file=groups.get("source_file"),
        explicit_line=groups.get("source_line"),
        explicit_request_id=groups.get("request_id"),
        log_line_number=line_num,
    )


def parse_single_header_line(
    line: str,
    line_num: int,
    preferred_format: str = "auto",
    default_service: str = "app",
    custom_re: re.Pattern[str] | None = None,
) -> RawParsedFields | None:
    """Attempt to parse a line as the start of a log event."""
    stripped = line.strip()
    if not stripped:
        return None

    if preferred_format == "jsonl":
        return _parse_json_line(stripped, line_num, default_service)
    if preferred_format == "python":
        return _parse_python_line(line, line_num, default_service)
    if preferred_format == "iso":
        return _parse_iso_line(line, line_num, default_service)
    if preferred_format == "syslog":
        return _parse_syslog_line(line, line_num, default_service)
    if preferred_format == "apache":
        return _parse_apache_line(line, line_num, default_service)
    if preferred_format == "nginx":
        return _parse_nginx_line(line, line_num, default_service)
    if preferred_format == "custom":
        return _parse_custom_line(line, line_num, default_service, custom_re)

    # Auto mode: try specific parsers in deterministic order
    if stripped.startswith("{"):
        return _parse_json_line(stripped, line_num, default_service)

    for parser_fn in (
        _parse_python_line,
        _parse_nginx_line,
        _parse_apache_line,
        _parse_syslog_line,
        _parse_iso_line,
    ):
        parsed = parser_fn(line, line_num, default_service)
        if parsed is not None:
            return parsed

    if custom_re:
        return _parse_custom_line(line, line_num, default_service, custom_re)

    return None


def is_multiline_continuation(line: str, active: RawParsedFields | None) -> bool:
    """Return True if `line` is part of a multiline traceback or continuation of `active`."""
    if active is None or active.parser_format == "jsonl":
        return False

    if TRACEBACK_START_RE.match(line):
        active.in_traceback_block = True
        return True

    if TRACEBACK_FRAME_RE.match(line):
        active.in_traceback_block = True
        return True

    if active.in_traceback_block and TRACEBACK_EXC_LINE_RE.match(line):
        return True

    # Indented continuation line immediately following an active event or traceback
    return bool(line.startswith(("  ", "\t")) and line.strip())


def finalize_raw_event(
    raw: RawParsedFields,
    event_id: int,
    log_file: str,
    redactor: SecretRedactor,
    default_year: int = 2026,
) -> LogEvent:
    """Normalize timestamps, extract metadata, apply security redaction, and create LogEvent."""
    dt_utc, raw_ts_str, tz_name, ts_valid = parse_and_normalize_timestamp(
        raw.raw_timestamp, default_year=default_year
    )

    raw_traceback = "\n".join(raw.traceback_lines) if raw.traceback_lines else None

    exc_type = extract_exception_type(
        raw.message, raw_traceback, explicit_exception=raw.explicit_exception
    )
    err_code = extract_error_code(raw.message, raw_traceback, explicit_code=raw.explicit_error_code)
    src_file, src_line = extract_source_location(
        raw.message,
        raw_traceback,
        explicit_file=raw.explicit_file,
        explicit_line=raw.explicit_line,
    )
    req_id = extract_request_id(
        raw.message,
        explicit_request_id=raw.explicit_request_id,
        extra=raw.extra_metadata,
    )

    # Redact sensitive values BEFORE storing in LogEvent
    safe_message = redactor.redact_text(raw.message)
    safe_traceback = redactor.redact_text(raw_traceback) if raw_traceback else None
    safe_extra = redactor.redact_dict(raw.extra_metadata)

    return LogEvent(
        event_id=event_id,
        timestamp=dt_utc,
        raw_timestamp=raw_ts_str,
        timezone_name=tz_name,
        severity=raw.severity,
        service=raw.service,
        logger=raw.logger,
        message=safe_message,
        traceback=safe_traceback,
        exception_type=exc_type,
        error_code=err_code,
        source_file=src_file,
        source_line=src_line,
        request_id=req_id,
        log_file=log_file,
        log_line_number=raw.log_line_number,
        parser_format=raw.parser_format,
        timestamp_valid=ts_valid,
        extra_metadata=safe_extra,
    )


def infer_default_service_from_filename(path: Path) -> str:
    """Infer a sensible fallback service name from a log filename."""
    name = path.name.lower()
    for suffix in (".gz", ".log", ".txt", ".jsonl", ".out", ".err"):
        name = name.replace(suffix, "")
    name = re.sub(r"\.\d+$", "", name)
    name = re.sub(r"[-_]\d{8}$", "", name)
    return name.strip("_-.") or "app"


def parse_file_stream(
    lines_iter: Iterator[tuple[int, str, bool]],
    file_path: Path,
    redactor: SecretRedactor,
    preferred_format: str = "auto",
    custom_pattern: str = "",
    start_event_id: int = 1,
    default_year: int = 2026,
) -> Iterator[tuple[LogEvent | None, ParseErrorRecord | None, FileIngestionStats]]:
    """Stream-parse a file's lines into normalized LogEvents and observable ParseErrorRecords.

    Yields:
        Tuples of (LogEvent | None, ParseErrorRecord | None, live FileIngestionStats).
    """
    display_path = str(file_path)
    stats = FileIngestionStats(file_path=display_path, detected_format=preferred_format)
    custom_re = re.compile(custom_pattern) if custom_pattern else None
    default_service = infer_default_service_from_filename(file_path)

    active_raw: RawParsedFields | None = None
    next_id = start_event_id
    detected_formats: set[str] = set()

    for line_num, line_text, had_encoding_err in lines_iter:
        stats.total_lines += 1
        if had_encoding_err:
            stats.encoding_errors += 1

        if not line_text.strip():
            continue

        # Attempt to parse as a new log event header
        parsed_header = parse_single_header_line(
            line_text,
            line_num,
            preferred_format=preferred_format,
            default_service=default_service,
            custom_re=custom_re,
        )

        if parsed_header is not None:
            # Flush previous active event if any
            if active_raw is not None:
                if active_raw.traceback_lines:
                    stats.multiline_events += 1
                ev = finalize_raw_event(
                    active_raw,
                    event_id=next_id,
                    log_file=display_path,
                    redactor=redactor,
                    default_year=default_year,
                )
                next_id += 1
                stats.parsed_events += 1
                if not ev.timestamp_valid:
                    stats.missing_timestamp_events += 1
                detected_formats.add(ev.parser_format)
                yield ev, None, stats

            active_raw = parsed_header
            continue

        # Not a new header: check if it is a multiline traceback/continuation of active_raw
        if is_multiline_continuation(line_text, active_raw):
            assert active_raw is not None
            active_raw.traceback_lines.append(line_text)
            continue

        # Otherwise, it is an unparseable / malformed line!
        stats.malformed_lines += 1
        safe_preview = redactor.redact_text(line_text[:180])
        err_record = ParseErrorRecord(
            log_file=display_path,
            line_number=line_num,
            raw_preview=safe_preview,
            reason=(
                "Malformed JSON record"
                if line_text.strip().startswith("{")
                else f"Line did not match expected format ({preferred_format})"
            ),
        )
        yield None, err_record, stats

    # Flush final buffered event at EOF
    if active_raw is not None:
        if active_raw.traceback_lines:
            stats.multiline_events += 1
        ev = finalize_raw_event(
            active_raw,
            event_id=next_id,
            log_file=display_path,
            redactor=redactor,
            default_year=default_year,
        )
        stats.parsed_events += 1
        if not ev.timestamp_valid:
            stats.missing_timestamp_events += 1
        detected_formats.add(ev.parser_format)
        yield ev, None, stats

    if preferred_format == "auto":
        if not detected_formats:
            stats.detected_format = "empty_or_unrecognized"
        elif len(detected_formats) == 1:
            stats.detected_format = next(iter(detected_formats))
        else:
            stats.detected_format = f"mixed({','.join(sorted(detected_formats))})"
