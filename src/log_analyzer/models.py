"""Data models for log events, failure groups, anomaly alerts, and analysis reports."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

SEVERITY_RANKS: dict[str, int] = {
    "UNKNOWN": 0,
    "DEBUG": 10,
    "INFO": 20,
    "WARNING": 30,
    "ERROR": 40,
    "CRITICAL": 50,
}

SEVERITY_ALIASES: dict[str, str] = {
    "DEBUG": "DEBUG",
    "DBG": "DEBUG",
    "TRACE": "DEBUG",
    "VERBOSE": "DEBUG",
    "INFO": "INFO",
    "INFORMATION": "INFO",
    "NOTICE": "INFO",
    "WARN": "WARNING",
    "WARNING": "WARNING",
    "WRN": "WARNING",
    "ERR": "ERROR",
    "ERROR": "ERROR",
    "SEVERE": "ERROR",
    "CRIT": "CRITICAL",
    "CRITICAL": "CRITICAL",
    "FATAL": "CRITICAL",
    "EMERG": "CRITICAL",
    "EMERGENCY": "CRITICAL",
    "ALERT": "CRITICAL",
    "PANIC": "CRITICAL",
}


def normalize_severity(raw: str | None, default: str = "UNKNOWN") -> str:
    """Normalize a raw severity string to one of DEBUG, INFO, WARNING, ERROR, CRITICAL, UNKNOWN."""
    if not raw:
        return default
    cleaned = raw.strip().upper()
    return SEVERITY_ALIASES.get(cleaned, default)


def severity_rank(severity: str) -> int:
    """Return numeric rank for severity comparison."""
    return SEVERITY_RANKS.get(severity.upper(), 0)


@dataclass
class LogEvent:
    """Represents a single normalized logical log event (including multiline tracebacks)."""

    event_id: int
    timestamp: datetime | None
    raw_timestamp: str | None
    timezone_name: str | None
    severity: str
    service: str
    logger: str
    message: str
    traceback: str | None = None
    exception_type: str | None = None
    error_code: str | None = None
    source_file: str | None = None
    source_line: int | None = None
    request_id: str | None = None
    log_file: str = ""
    log_line_number: int = 0
    parser_format: str = "unknown"
    category_id: str = "normal_operation"
    category_name: str = "Normal Operation"
    matched_rule: str = ""
    investigation_hint: str = ""
    fingerprint: str = ""
    fingerprint_template: str = ""
    fingerprint_confidence: str = "high"
    timestamp_valid: bool = True
    extra_metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def full_text(self) -> str:
        """Return message combined with traceback if present."""
        if self.traceback:
            return f"{self.message}\n{self.traceback}"
        return self.message

    def is_failure(self, min_severity: str = "ERROR") -> bool:
        """Return True if the event severity meets or exceeds the failure threshold."""
        return severity_rank(self.severity) >= severity_rank(min_severity)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the event into a JSON-compatible dictionary."""
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "raw_timestamp": self.raw_timestamp,
            "timezone_name": self.timezone_name,
            "severity": self.severity,
            "service": self.service,
            "logger": self.logger,
            "message": self.message,
            "traceback": self.traceback,
            "exception_type": self.exception_type,
            "error_code": self.error_code,
            "source_file": self.source_file,
            "source_line": self.source_line,
            "request_id": self.request_id,
            "log_file": self.log_file,
            "log_line_number": self.log_line_number,
            "parser_format": self.parser_format,
            "category_id": self.category_id,
            "category_name": self.category_name,
            "matched_rule": self.matched_rule,
            "investigation_hint": self.investigation_hint,
            "fingerprint": self.fingerprint,
            "fingerprint_template": self.fingerprint_template,
            "fingerprint_confidence": self.fingerprint_confidence,
            "timestamp_valid": self.timestamp_valid,
            "extra_metadata": self.extra_metadata,
        }


@dataclass
class ParseErrorRecord:
    """Observable record of an unparseable line or file read error."""

    log_file: str
    line_number: int
    raw_preview: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "log_file": self.log_file,
            "line_number": self.line_number,
            "raw_preview": self.raw_preview,
            "reason": self.reason,
        }


@dataclass
class FileIngestionStats:
    """Statistics collected while ingesting a single log file."""

    file_path: str
    detected_format: str = "auto"
    total_lines: int = 0
    parsed_events: int = 0
    multiline_events: int = 0
    malformed_lines: int = 0
    duplicate_events_skipped: int = 0
    filtered_events_skipped: int = 0
    missing_timestamp_events: int = 0
    skipped_incremental: bool = False
    encoding_errors: int = 0
    status: str = "ok"
    error_message: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "detected_format": self.detected_format,
            "total_lines": self.total_lines,
            "parsed_events": self.parsed_events,
            "multiline_events": self.multiline_events,
            "malformed_lines": self.malformed_lines,
            "duplicate_events_skipped": self.duplicate_events_skipped,
            "filtered_events_skipped": self.filtered_events_skipped,
            "missing_timestamp_events": self.missing_timestamp_events,
            "skipped_incremental": self.skipped_incremental,
            "encoding_errors": self.encoding_errors,
            "status": self.status,
            "error_message": self.error_message,
        }


@dataclass
class ErrorGroup:
    """Aggregated summary of a recurring failure identified by error fingerprint."""

    fingerprint: str
    template: str
    category_id: str
    category_name: str
    exception_type: str | None
    error_code: str | None
    count: int
    first_seen: datetime | None
    last_seen: datetime | None
    services: list[str] = field(default_factory=list)
    severity_distribution: dict[str, int] = field(default_factory=dict)
    source_files: list[str] = field(default_factory=list)
    log_files: list[str] = field(default_factory=list)
    sample_messages: list[str] = field(default_factory=list)
    sample_tracebacks: list[str] = field(default_factory=list)
    sample_locations: list[str] = field(default_factory=list)
    sample_event_ids: list[int] = field(default_factory=list)
    frequency_by_window: dict[str, int] = field(default_factory=dict)
    confidence: str = "high"
    confidence_note: str = ""
    investigation_hint: str = ""
    matched_rule: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "template": self.template,
            "category_id": self.category_id,
            "category_name": self.category_name,
            "exception_type": self.exception_type,
            "error_code": self.error_code,
            "count": self.count,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "services": self.services,
            "severity_distribution": self.severity_distribution,
            "source_files": self.source_files,
            "log_files": self.log_files,
            "sample_messages": self.sample_messages,
            "sample_tracebacks": self.sample_tracebacks,
            "sample_locations": self.sample_locations,
            "sample_event_ids": self.sample_event_ids,
            "frequency_by_window": self.frequency_by_window,
            "confidence": self.confidence,
            "confidence_note": self.confidence_note,
            "investigation_hint": self.investigation_hint,
            "matched_rule": self.matched_rule,
        }


@dataclass
class AnomalyAlert:
    """Represents a detected error spike or threshold violation in a time window."""

    alert_id: str
    window_start: datetime
    window_end: datetime
    window_size: str
    alert_type: str  # "confirmed_threshold", "statistical_anomaly", or "combined"
    severity_label: str  # "HIGH", "MEDIUM", "CRITICAL"
    observed_count: int
    baseline_mean: float
    baseline_median: float
    baseline_mad: float
    ratio_over_baseline: float
    modified_z_score: float
    threshold_limit: int
    explanation: str
    top_category: str = ""
    top_service: str = ""
    top_fingerprint: str = ""
    sample_message: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "alert_id": self.alert_id,
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "window_size": self.window_size,
            "alert_type": self.alert_type,
            "severity_label": self.severity_label,
            "observed_count": self.observed_count,
            "baseline_mean": round(self.baseline_mean, 3),
            "baseline_median": round(self.baseline_median, 3),
            "baseline_mad": round(self.baseline_mad, 3),
            "ratio_over_baseline": round(self.ratio_over_baseline, 3),
            "modified_z_score": round(self.modified_z_score, 3),
            "threshold_limit": self.threshold_limit,
            "explanation": self.explanation,
            "top_category": self.top_category,
            "top_service": self.top_service,
            "top_fingerprint": self.top_fingerprint,
            "sample_message": self.sample_message,
        }


@dataclass
class TimeBucketMetric:
    """Time bucket aggregation record for time-series analysis and plotting."""

    window_start: datetime
    total_events: int = 0
    error_events: int = 0
    warning_events: int = 0
    rolling_baseline: float = 0.0
    is_anomaly: bool = False
    alert_type: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "window_start": self.window_start.isoformat(),
            "total_events": self.total_events,
            "error_events": self.error_events,
            "warning_events": self.warning_events,
            "rolling_baseline": round(self.rolling_baseline, 3),
            "is_anomaly": self.is_anomaly,
            "alert_type": self.alert_type,
        }


@dataclass
class AnalysisResult:
    """Complete result object produced by a log analysis run."""

    run_id: str
    generated_at: datetime
    input_paths: list[str]
    config_summary: dict[str, Any]
    total_files_scanned: int = 0
    total_files_skipped_incremental: int = 0
    total_lines_read: int = 0
    total_events_parsed: int = 0
    total_events_analyzed: int = 0
    total_error_events: int = 0
    total_warning_events: int = 0
    malformed_lines_count: int = 0
    missing_timestamp_count: int = 0
    duplicate_events_skipped: int = 0
    filtered_events_skipped: int = 0
    redactions_applied: int = 0
    time_range_start: datetime | None = None
    time_range_end: datetime | None = None
    severity_counts: dict[str, int] = field(default_factory=dict)
    category_counts: dict[str, int] = field(default_factory=dict)
    service_counts: dict[str, int] = field(default_factory=dict)
    service_error_counts: dict[str, int] = field(default_factory=dict)
    error_groups: list[ErrorGroup] = field(default_factory=list)
    anomaly_alerts: list[AnomalyAlert] = field(default_factory=list)
    anomaly_diagnostics: dict[str, Any] = field(default_factory=dict)
    time_series_buckets: list[TimeBucketMetric] = field(default_factory=list)
    file_stats: list[FileIngestionStats] = field(default_factory=list)
    parse_errors: list[ParseErrorRecord] = field(default_factory=list)
    high_priority_findings: list[dict[str, Any]] = field(default_factory=list)
    trend_summary: str = "Stable"

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "generated_at": self.generated_at.isoformat(),
            "input_paths": self.input_paths,
            "config_summary": self.config_summary,
            "summary": {
                "total_files_scanned": self.total_files_scanned,
                "total_files_skipped_incremental": self.total_files_skipped_incremental,
                "total_lines_read": self.total_lines_read,
                "total_events_parsed": self.total_events_parsed,
                "total_events_analyzed": self.total_events_analyzed,
                "total_error_events": self.total_error_events,
                "total_warning_events": self.total_warning_events,
                "malformed_lines_count": self.malformed_lines_count,
                "missing_timestamp_count": self.missing_timestamp_count,
                "duplicate_events_skipped": self.duplicate_events_skipped,
                "filtered_events_skipped": self.filtered_events_skipped,
                "redactions_applied": self.redactions_applied,
                "time_range_start": (
                    self.time_range_start.isoformat() if self.time_range_start else None
                ),
                "time_range_end": (
                    self.time_range_end.isoformat() if self.time_range_end else None
                ),
                "unique_error_groups": len(self.error_groups),
                "anomaly_alerts_triggered": len(self.anomaly_alerts),
                "trend_summary": self.trend_summary,
            },
            "severity_counts": self.severity_counts,
            "category_counts": self.category_counts,
            "service_counts": self.service_counts,
            "service_error_counts": self.service_error_counts,
            "high_priority_findings": self.high_priority_findings,
            "error_groups": [g.to_dict() for g in self.error_groups],
            "anomaly_alerts": [a.to_dict() for a in self.anomaly_alerts],
            "anomaly_diagnostics": self.anomaly_diagnostics,
            "time_series_buckets": [b.to_dict() for b in self.time_series_buckets],
            "file_stats": [f.to_dict() for f in self.file_stats],
            "parse_errors": [p.to_dict() for p in self.parse_errors[:200]],
        }
