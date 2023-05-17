"""End-to-end analysis pipeline coordinating ingestion, parsing, classification, anomaly detection, and reporting."""

from __future__ import annotations

import logging
import uuid
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from log_analyzer.aggregator import (
    EventFilter,
    FilterCriteria,
    aggregate_error_groups,
    build_high_priority_findings,
    compute_dedup_signature,
)
from log_analyzer.anomaly import detect_anomalies_and_series
from log_analyzer.classifier import FailureClassifier
from log_analyzer.config import AnalyzerConfig
from log_analyzer.discovery import (
    compute_file_fingerprint,
    discover_log_files,
    stream_file_lines,
)
from log_analyzer.fingerprinter import ErrorFingerprinter
from log_analyzer.models import (
    AnalysisResult,
    FileIngestionStats,
    LogEvent,
    ParseErrorRecord,
    severity_rank,
)
from log_analyzer.parsers import parse_file_stream
from log_analyzer.persistence import IncrementalStateStore
from log_analyzer.reporter import (
    export_csv_reports,
    export_html_report,
    export_json_report,
)
from log_analyzer.security import SecretRedactor
from log_analyzer.visualizer import generate_all_charts

logger = logging.getLogger("log_analyzer")


def run_analysis_pipeline(
    input_paths: list[str | Path],
    config: AnalyzerConfig,
    criteria: FilterCriteria | None = None,
    format_override: str | None = None,
    file_filter: str | None = None,
    incremental: bool = False,
    state_db_path: str | Path | None = None,
    output_dir: str | Path | None = None,
    export_formats: set[str] | None = None,
) -> tuple[AnalysisResult, dict[str, Path]]:
    """Execute the complete log analysis pipeline and optional report generation.

    Returns:
        Tuple of (AnalysisResult, dict mapping artifact names to generated Paths).
    """
    filter_criteria = criteria or FilterCriteria(
        exclude_patterns=list(config.exclude_patterns),
        top_n=config.top_n,
    )
    if not filter_criteria.exclude_patterns and config.exclude_patterns:
        filter_criteria.exclude_patterns = list(config.exclude_patterns)

    event_filter = EventFilter(filter_criteria)
    redactor = SecretRedactor(config.security)
    classifier = FailureClassifier(config)
    fingerprinter = ErrorFingerprinter(config.fingerprinting)

    state_store: IncrementalStateStore | None = None
    if incremental or state_db_path:
        db_target = state_db_path or Path(".log_analyzer_state.db")
        state_store = IncrementalStateStore(db_target)

    discovered_files, discovery_warnings = discover_log_files(
        input_paths,
        recursive=config.recursive,
        file_filter=file_filter,
    )
    for warn_msg in discovery_warnings:
        logger.warning("%s", warn_msg)

    if not discovered_files:
        raise FileNotFoundError(
            f"No readable log files found matching inputs: {[str(p) for p in input_paths]}"
        )

    preferred_fmt = (format_override or config.default_format or "auto").lower()
    seen_dedup_hashes: set[str] = set()
    analyzed_events: list[LogEvent] = []
    all_parse_errors: list[ParseErrorRecord] = []
    all_file_stats: list[FileIngestionStats] = []

    total_lines_read = 0
    total_events_parsed = 0
    duplicate_skipped = 0
    filtered_skipped = 0
    missing_ts_count = 0
    malformed_count = 0
    files_skipped_incremental = 0
    next_event_id = 1

    for file_path in discovered_files:
        file_fp = ""
        if state_store is not None:
            try:
                file_fp = compute_file_fingerprint(file_path)
                if incremental and state_store.is_file_unchanged(file_path, file_fp):
                    logger.info("Skipping unchanged file (incremental mode): %s", file_path)
                    files_skipped_incremental += 1
                    all_file_stats.append(
                        FileIngestionStats(
                            file_path=str(file_path),
                            detected_format="skipped_incremental",
                            skipped_incremental=True,
                            status="skipped_unchanged",
                        )
                    )
                    continue
            except OSError as exc:
                logger.warning("Unable to fingerprint file %s: %s", file_path, exc)

        try:
            lines_iter = stream_file_lines(file_path, encoding=config.encoding)
            current_stats: FileIngestionStats | None = None

            for ev, err_rec, f_stats in parse_file_stream(
                lines_iter=lines_iter,
                file_path=file_path,
                redactor=redactor,
                preferred_format=preferred_fmt,
                custom_pattern=config.custom_parser_pattern,
                start_event_id=next_event_id,
            ):
                current_stats = f_stats
                if err_rec is not None:
                    malformed_count += 1
                    if len(all_parse_errors) < 500:
                        all_parse_errors.append(err_rec)
                    continue

                if ev is None:
                    continue

                next_event_id = ev.event_id + 1
                total_events_parsed += 1
                if not ev.timestamp_valid:
                    missing_ts_count += 1

                # Deduplicate rotated log overlaps if configured
                if config.deduplicate_rotated:
                    sig = compute_dedup_signature(ev)
                    if sig in seen_dedup_hashes:
                        duplicate_skipped += 1
                        f_stats.duplicate_events_skipped += 1
                        continue
                    seen_dedup_hashes.add(sig)

                # Classify and fingerprint before filtering so category filters work
                classifier.classify(ev)
                if (
                    severity_rank(ev.severity) >= severity_rank(config.failure_severity_threshold)
                    or ev.category_id != "normal_operation"
                ):
                    fingerprinter.fingerprint_event(ev)

                # Evaluate filter criteria
                if not event_filter.matches(ev):
                    filtered_skipped += 1
                    f_stats.filtered_events_skipped += 1
                    continue

                analyzed_events.append(ev)

            if current_stats is None:
                # File was completely empty
                current_stats = FileIngestionStats(
                    file_path=str(file_path),
                    detected_format="empty",
                    status="ok",
                )
            total_lines_read += current_stats.total_lines
            all_file_stats.append(current_stats)

            if state_store is not None and file_fp:
                state_store.record_processed_file(file_path, file_fp, current_stats)

        except (PermissionError, OSError, EOFError) as exc:
            logger.error("Failed reading log file %s: %s", file_path, exc)
            all_file_stats.append(
                FileIngestionStats(
                    file_path=str(file_path),
                    detected_format="error",
                    status="read_error",
                    error_message=str(exc),
                )
            )
            all_parse_errors.append(
                ParseErrorRecord(
                    log_file=str(file_path),
                    line_number=0,
                    raw_preview="",
                    reason=f"File read error: {exc}",
                )
            )

    # Calculate aggregate counts
    sev_counter: Counter[str] = Counter()
    cat_counter: Counter[str] = Counter()
    srv_counter: Counter[str] = Counter()
    srv_err_counter: Counter[str] = Counter()
    min_fail_rank = severity_rank(config.failure_severity_threshold)
    warn_rank = severity_rank("WARNING")

    total_errors = 0
    total_warnings = 0
    min_ts: datetime | None = None
    max_ts: datetime | None = None

    for ev in analyzed_events:
        sev_counter[ev.severity] += 1
        cat_counter[ev.category_name] += 1
        srv_counter[ev.service] += 1

        ev_rank = severity_rank(ev.severity)
        if ev_rank >= min_fail_rank:
            total_errors += 1
            srv_err_counter[ev.service] += 1
        elif ev_rank == warn_rank:
            total_warnings += 1

        if ev.timestamp is not None and ev.timestamp_valid:
            if min_ts is None or ev.timestamp < min_ts:
                min_ts = ev.timestamp
            if max_ts is None or ev.timestamp > max_ts:
                max_ts = ev.timestamp

    # Aggregate error groups
    error_groups = aggregate_error_groups(
        analyzed_events,
        fingerprinter=fingerprinter,
        config=config,
        sort_by=filter_criteria.sort_by,
        top_n=filter_criteria.top_n,
    )

    # Run anomaly and spike detection
    time_buckets, anomaly_alerts, anom_diagnostics, trend_summary = detect_anomalies_and_series(
        analyzed_events,
        config=config.anomaly_detection,
        failure_severity=config.failure_severity_threshold,
    )

    high_priority = build_high_priority_findings(
        error_groups=error_groups,
        anomaly_alerts=anomaly_alerts,
        total_error_events=total_errors,
    )

    run_id = f"run-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    config_summary: dict[str, Any] = {
        "encoding": config.encoding,
        "recursive": config.recursive,
        "format": preferred_fmt,
        "deduplicate_rotated": config.deduplicate_rotated,
        "failure_severity_threshold": config.failure_severity_threshold,
        "time_window": config.anomaly_detection.time_window,
        "absolute_threshold": config.anomaly_detection.absolute_threshold,
        "ratio_threshold": config.anomaly_detection.ratio_threshold,
        "mad_z_threshold": config.anomaly_detection.mad_z_threshold,
        "min_spike_count": config.anomaly_detection.min_spike_count,
        "redaction_enabled": config.security.enable_redaction,
    }

    result = AnalysisResult(
        run_id=run_id,
        generated_at=datetime.now(UTC),
        input_paths=[str(p) for p in input_paths],
        config_summary=config_summary,
        total_files_scanned=len(discovered_files),
        total_files_skipped_incremental=files_skipped_incremental,
        total_lines_read=total_lines_read,
        total_events_parsed=total_events_parsed,
        total_events_analyzed=len(analyzed_events),
        total_error_events=total_errors,
        total_warning_events=total_warnings,
        malformed_lines_count=malformed_count,
        missing_timestamp_count=missing_ts_count,
        duplicate_events_skipped=duplicate_skipped,
        filtered_events_skipped=filtered_skipped,
        redactions_applied=redactor.redactions_count,
        time_range_start=min_ts,
        time_range_end=max_ts,
        severity_counts=dict(sev_counter),
        category_counts=dict(cat_counter),
        service_counts=dict(srv_counter),
        service_error_counts=dict(srv_err_counter),
        error_groups=error_groups,
        anomaly_alerts=anomaly_alerts,
        anomaly_diagnostics=anom_diagnostics,
        time_series_buckets=time_buckets,
        file_stats=all_file_stats,
        parse_errors=all_parse_errors,
        high_priority_findings=high_priority,
        trend_summary=trend_summary,
    )

    if state_store is not None:
        state_store.record_analysis_run(result)

    generated_paths: dict[str, Path] = {}
    if output_dir is not None:
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)
        formats = export_formats or {"json", "csv", "html", "png"}

        chart_uris: dict[str, tuple[Path, str]] = {}
        if "png" in formats or "html" in formats or "all" in formats:
            chart_uris = generate_all_charts(result, out_path)
            for c_key, (c_path, _) in chart_uris.items():
                generated_paths[f"chart_{c_key}"] = c_path

        if "json" in formats or "all" in formats:
            generated_paths["json_report"] = export_json_report(result, out_path)

        if "csv" in formats or "all" in formats:
            csv_paths = export_csv_reports(
                result,
                out_path,
                csv_formula_protection=config.security.csv_formula_protection,
            )
            generated_paths.update(csv_paths)

        if "html" in formats or "all" in formats:
            generated_paths["html_report"] = export_html_report(
                result, out_path, chart_uris=chart_uris
            )

    return result, generated_paths
