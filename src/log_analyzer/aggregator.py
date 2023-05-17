"""Event filtering, deduplication, fingerprint group aggregation, and priority ranking."""

from __future__ import annotations

import hashlib
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from log_analyzer.config import AnalyzerConfig
from log_analyzer.fingerprinter import ErrorFingerprinter
from log_analyzer.models import (
    AnomalyAlert,
    ErrorGroup,
    LogEvent,
    severity_rank,
)


@dataclass
class FilterCriteria:
    """User-specified filtering criteria for log events."""

    since: datetime | None = None
    until: datetime | None = None
    min_severity: str | None = None
    exact_severity: str | None = None
    service: str | None = None
    category: str | None = None
    search_pattern: str | None = None
    exclude_patterns: list[str] = field(default_factory=list)
    sort_by: str = "count"  # "count", "last_seen", "first_seen", "severity"
    top_n: int = 15


class EventFilter:
    """Evaluates whether a normalized LogEvent matches active filter criteria."""

    def __init__(self, criteria: FilterCriteria) -> None:
        self.criteria = criteria
        self.min_rank = severity_rank(criteria.min_severity) if criteria.min_severity else 0
        self.exact_sev = criteria.exact_severity.upper() if criteria.exact_severity else None
        self.service_lower = criteria.service.lower() if criteria.service else None
        self.category_lower = criteria.category.lower() if criteria.category else None
        self.search_re = (
            re.compile(criteria.search_pattern, re.IGNORECASE) if criteria.search_pattern else None
        )
        self.exclude_res = [
            re.compile(pat, re.IGNORECASE) for pat in criteria.exclude_patterns if pat
        ]

    def matches(self, event: LogEvent) -> bool:
        """Return True if the event passes all active filters."""
        # 1. Exclusion patterns
        full_text = event.full_text
        for ex_re in self.exclude_res:
            if ex_re.search(full_text):
                return False

        # 2. Time range filter
        if self.criteria.since is not None and (
            event.timestamp is None or event.timestamp < self.criteria.since
        ):
            return False
        if self.criteria.until is not None and (
            event.timestamp is None or event.timestamp > self.criteria.until
        ):
            return False

        # 3. Severity filter
        if self.exact_sev and event.severity.upper() != self.exact_sev:
            return False
        if self.min_rank > 0 and severity_rank(event.severity) < self.min_rank:
            return False

        # 4. Service filter
        if self.service_lower and self.service_lower not in event.service.lower():
            return False

        # 5. Category filter
        if self.category_lower and (
            self.category_lower not in event.category_id.lower()
            and self.category_lower not in event.category_name.lower()
        ):
            return False

        # 6. Keyword / Regex search
        if self.search_re is None:
            return True
        return bool(
            self.search_re.search(full_text)
            or self.search_re.search(event.service)
            or self.search_re.search(event.logger)
            or (event.request_id and self.search_re.search(event.request_id))
        )


def compute_dedup_signature(event: LogEvent) -> str:
    """Compute a deterministic signature to identify duplicate records across rotated files."""
    ts_key = event.raw_timestamp or (event.timestamp.isoformat() if event.timestamp else "no_ts")
    payload = f"{ts_key}|{event.severity}|{event.service}|{event.logger}|{event.message}|{event.traceback or ''}"
    return hashlib.sha1(payload.encode("utf-8")).hexdigest()


@dataclass
class _MutableGroupAccumulator:
    """Internal accumulator for building an ErrorGroup in a single pass."""

    fingerprint: str
    template: str
    category_id: str
    category_name: str
    exception_type: str | None
    error_code: str | None
    confidence: str
    confidence_note: str
    investigation_hint: str
    matched_rule: str
    count: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    services: set[str] = field(default_factory=set)
    severities: Counter[str] = field(default_factory=Counter)
    source_files: set[str] = field(default_factory=set)
    log_files: set[str] = field(default_factory=set)
    sample_messages: list[str] = field(default_factory=list)
    sample_tracebacks: list[str] = field(default_factory=list)
    sample_locations: list[str] = field(default_factory=list)
    sample_event_ids: list[int] = field(default_factory=list)
    frequency_by_window: Counter[str] = field(default_factory=Counter)


def aggregate_error_groups(
    events: list[LogEvent],
    fingerprinter: ErrorFingerprinter,
    config: AnalyzerConfig,
    sort_by: str = "count",
    top_n: int | None = None,
) -> list[ErrorGroup]:
    """Group failure events by fingerprint and calculate detailed group statistics."""
    min_fail_rank = severity_rank(config.failure_severity_threshold)
    accumulators: dict[str, _MutableGroupAccumulator] = {}

    for ev in events:
        if severity_rank(ev.severity) < min_fail_rank and ev.category_id == "normal_operation":
            continue

        fp = ev.fingerprint
        if not fp:
            fingerprinter.fingerprint_event(ev)
            fp = ev.fingerprint

        acc = accumulators.get(fp)
        if acc is None:
            conf, conf_note = fingerprinter.assess_confidence(
                ev.fingerprint_template, ev.exception_type, ev.error_code
            )
            acc = _MutableGroupAccumulator(
                fingerprint=fp,
                template=ev.fingerprint_template,
                category_id=ev.category_id,
                category_name=ev.category_name,
                exception_type=ev.exception_type,
                error_code=ev.error_code,
                confidence=conf,
                confidence_note=conf_note,
                investigation_hint=ev.investigation_hint,
                matched_rule=ev.matched_rule,
            )
            accumulators[fp] = acc

        acc.count += 1
        if ev.timestamp is not None and ev.timestamp_valid:
            if acc.first_seen is None or ev.timestamp < acc.first_seen:
                acc.first_seen = ev.timestamp
            if acc.last_seen is None or ev.timestamp > acc.last_seen:
                acc.last_seen = ev.timestamp
            hour_bucket = ev.timestamp.strftime("%Y-%m-%d %H:00Z")
            acc.frequency_by_window[hour_bucket] += 1

        if ev.service:
            acc.services.add(ev.service)
        acc.severities[ev.severity] += 1
        if ev.source_file:
            loc_str = f"{ev.source_file}:{ev.source_line}" if ev.source_line else ev.source_file
            acc.source_files.add(loc_str)
        if ev.log_file:
            acc.log_files.add(os.path.basename(ev.log_file))

        if not acc.exception_type and ev.exception_type:
            acc.exception_type = ev.exception_type
        if not acc.error_code and ev.error_code:
            acc.error_code = ev.error_code

        if len(acc.sample_messages) < 3 and ev.message not in acc.sample_messages:
            acc.sample_messages.append(ev.message)
        if (
            ev.traceback
            and len(acc.sample_tracebacks) < 2
            and ev.traceback not in acc.sample_tracebacks
        ):
            acc.sample_tracebacks.append(ev.traceback)
        if len(acc.sample_locations) < 5:
            loc_ref = f"{os.path.basename(ev.log_file)}:{ev.log_line_number}"
            if loc_ref not in acc.sample_locations:
                acc.sample_locations.append(loc_ref)
        if len(acc.sample_event_ids) < 10:
            acc.sample_event_ids.append(ev.event_id)

    groups: list[ErrorGroup] = []
    for acc in accumulators.values():
        groups.append(
            ErrorGroup(
                fingerprint=acc.fingerprint,
                template=acc.template,
                category_id=acc.category_id,
                category_name=acc.category_name,
                exception_type=acc.exception_type,
                error_code=acc.error_code,
                count=acc.count,
                first_seen=acc.first_seen,
                last_seen=acc.last_seen,
                services=sorted(acc.services),
                severity_distribution=dict(acc.severities),
                source_files=sorted(acc.source_files),
                log_files=sorted(acc.log_files),
                sample_messages=acc.sample_messages,
                sample_tracebacks=acc.sample_tracebacks,
                sample_locations=acc.sample_locations,
                sample_event_ids=acc.sample_event_ids,
                frequency_by_window=dict(sorted(acc.frequency_by_window.items())),
                confidence=acc.confidence,
                confidence_note=acc.confidence_note,
                investigation_hint=acc.investigation_hint,
                matched_rule=acc.matched_rule,
            )
        )

    # Sort groups deterministically
    if sort_by == "last_seen":
        groups.sort(
            key=lambda g: (
                g.last_seen.timestamp() if g.last_seen else float("-inf"),
                g.count,
            ),
            reverse=True,
        )
    elif sort_by == "first_seen":
        groups.sort(
            key=lambda g: (
                g.first_seen.timestamp() if g.first_seen else float("inf"),
                -g.count,
            )
        )
    elif sort_by == "severity":
        groups.sort(
            key=lambda g: (
                max((severity_rank(s) for s in g.severity_distribution), default=0),
                g.count,
                g.fingerprint,
            ),
            reverse=True,
        )
    else:
        # Default: count descending, then highest severity, then fingerprint
        groups.sort(
            key=lambda g: (
                g.count,
                max((severity_rank(s) for s in g.severity_distribution), default=0),
                g.fingerprint,
            ),
            reverse=True,
        )

    if top_n is not None and top_n > 0:
        return groups[:top_n]
    return groups


def build_high_priority_findings(
    error_groups: list[ErrorGroup],
    anomaly_alerts: list[AnomalyAlert],
    total_error_events: int,
) -> list[dict[str, Any]]:
    """Synthesize prioritized findings answering what to investigate first and why."""
    findings: list[dict[str, Any]] = []

    # 1. Include top critical/high anomaly spikes
    for alert in anomaly_alerts[:3]:
        findings.append(
            {
                "priority": "P1 - URGENT SPIKE"
                if alert.severity_label == "CRITICAL"
                else "P2 - ANOMALY SPIKE",
                "title": (
                    f"Error spike of {alert.observed_count} failures in {alert.window_size} window "
                    f"({alert.window_start.strftime('%Y-%m-%d %H:%M:%SZ')})"
                ),
                "impact": (
                    f"{alert.ratio_over_baseline:.1f}x normal baseline (type: {alert.alert_type}); "
                    f"primarily affecting service '{alert.top_service}' ({alert.top_category})."
                ),
                "first_seen": alert.window_start.isoformat(),
                "last_seen": alert.window_end.isoformat(),
                "recommendation": alert.explanation,
            }
        )

    # 2. Include top recurring error groups by volume and severity
    for idx, grp in enumerate(error_groups[:5], start=1):
        share_pct = (grp.count / max(total_error_events, 1)) * 100.0
        has_critical = grp.severity_distribution.get("CRITICAL", 0) > 0
        prio_label = (
            "P1 - CRITICAL FAILURE"
            if has_critical or share_pct >= 25.0
            else ("P2 - RECURRING ERROR" if idx <= 3 else "P3 - INVESTIGATE")
        )
        findings.append(
            {
                "priority": prio_label,
                "title": f"[{grp.category_name}] {grp.template[:110]}",
                "impact": (
                    f"{grp.count} occurrences ({share_pct:.1f}% of all errors) across "
                    f"service(s): {', '.join(grp.services) or 'unknown'}. "
                    f"Fingerprint: {grp.fingerprint}."
                ),
                "first_seen": grp.first_seen.isoformat() if grp.first_seen else "Unknown",
                "last_seen": grp.last_seen.isoformat() if grp.last_seen else "Unknown",
                "recommendation": grp.investigation_hint,
            }
        )

    return findings
