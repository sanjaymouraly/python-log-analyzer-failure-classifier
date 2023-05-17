"""Unit tests for event filtering, deduplication, and error group aggregation."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from log_analyzer.aggregator import (
    EventFilter,
    FilterCriteria,
    aggregate_error_groups,
    build_high_priority_findings,
    compute_dedup_signature,
)
from log_analyzer.config import create_default_config
from log_analyzer.fingerprinter import ErrorFingerprinter
from log_analyzer.models import LogEvent


def _make_event(**kwargs) -> LogEvent:
    defaults = {
        "event_id": 1,
        "timestamp": datetime(2026, 1, 1, 12, 0, 0, tzinfo=UTC),
        "raw_timestamp": "2026-01-01T12:00:00+00:00",
        "timezone_name": "UTC",
        "severity": "ERROR",
        "service": "test-service",
        "logger": "test.logger",
        "message": "Test error message",
    }
    defaults.update(kwargs)
    return LogEvent(**defaults)


@pytest.fixture
def fingerprinter():
    return ErrorFingerprinter(create_default_config().fingerprinting)


@pytest.fixture
def sample_events():
    return [
        _make_event(
            event_id=1,
            message="Database connection failed to host1",
            exception_type="ConnectionError",
            error_code="ERR_001",
        ),
        _make_event(
            event_id=2,
            message="Database connection failed to host1",
            exception_type="ConnectionError",
            error_code="ERR_001",
        ),
        _make_event(
            event_id=3,
            message="Database connection failed to host1",
            exception_type="ConnectionError",
            error_code="ERR_001",
        ),
        _make_event(
            event_id=4,
            message="Authentication failed for user1",
            exception_type="AuthError",
            error_code="AUTH_001",
        ),
        _make_event(
            event_id=5,
            message="Authentication failed for user1",
            exception_type="AuthError",
            error_code="AUTH_001",
        ),
        _make_event(
            event_id=6,
            severity="INFO",
            message="Normal operation",
        ),
    ]


class TestEventFilter:
    def test_filter_by_min_severity(self, sample_events):
        criteria = FilterCriteria(min_severity="ERROR")
        filt = EventFilter(criteria)
        matches = [e for e in sample_events if filt.matches(e)]
        assert len(matches) == 5
        assert all(e.severity == "ERROR" for e in matches)

    def test_filter_by_exact_severity(self, sample_events):
        criteria = FilterCriteria(exact_severity="INFO")
        filt = EventFilter(criteria)
        matches = [e for e in sample_events if filt.matches(e)]
        assert len(matches) == 1
        assert matches[0].severity == "INFO"

    def test_filter_by_service(self, sample_events):
        criteria = FilterCriteria(service="test-service")
        filt = EventFilter(criteria)
        matches = [e for e in sample_events if filt.matches(e)]
        assert len(matches) == 6

    def test_filter_by_category(self, sample_events):
        criteria = FilterCriteria(category="database")
        filt = EventFilter(criteria)
        for e in sample_events:
            e.category_id = "database" if "Database" in e.message else "other"
        matches = [e for e in sample_events if filt.matches(e)]
        assert len(matches) == 3

    def test_filter_by_search_pattern(self, sample_events):
        criteria = FilterCriteria(search_pattern="Database")
        filt = EventFilter(criteria)
        matches = [e for e in sample_events if filt.matches(e)]
        assert len(matches) == 3

    def test_filter_by_search_regex(self, sample_events):
        criteria = FilterCriteria(search_pattern=r"Auth.*failed")
        filt = EventFilter(criteria)
        matches = [e for e in sample_events if filt.matches(e)]
        assert len(matches) == 2

    def test_filter_by_time_range(self, sample_events):
        for i, e in enumerate(sample_events):
            e.timestamp = datetime(2026, 1, 1, 12, i, 0, tzinfo=UTC)
        criteria = FilterCriteria(
            since=datetime(2026, 1, 1, 12, 1, tzinfo=UTC),
            until=datetime(2026, 1, 1, 12, 3, tzinfo=UTC),
        )
        filt = EventFilter(criteria)
        matches = [e for e in sample_events if filt.matches(e)]
        assert len(matches) == 3

    def test_filter_by_exclude_patterns(self, sample_events):
        criteria = FilterCriteria(exclude_patterns=["Auth"])
        filt = EventFilter(criteria)
        matches = [e for e in sample_events if filt.matches(e)]
        assert len(matches) == 4

    def test_filter_no_criteria_matches_all(self, sample_events):
        criteria = FilterCriteria()
        filt = EventFilter(criteria)
        matches = [e for e in sample_events if filt.matches(e)]
        assert len(matches) == 6

    def test_filter_timestamp_none_excluded(self, sample_events):
        sample_events[0].timestamp = None
        criteria = FilterCriteria(since=datetime(2026, 1, 1, tzinfo=UTC))
        filt = EventFilter(criteria)
        matches = [e for e in sample_events if filt.matches(e)]
        assert sample_events[0] not in matches


class TestComputeDedupSignature:
    def test_same_content_same_signature(self):
        event1 = _make_event(message="Same error message")
        event2 = _make_event(message="Same error message")
        assert compute_dedup_signature(event1) == compute_dedup_signature(event2)

    def test_different_message_different_signature(self):
        event1 = _make_event(message="Error message A")
        event2 = _make_event(message="Error message B")
        assert compute_dedup_signature(event1) != compute_dedup_signature(event2)

    def test_different_severity_different_signature(self):
        event1 = _make_event(severity="ERROR", message="Same message")
        event2 = _make_event(severity="WARNING", message="Same message")
        assert compute_dedup_signature(event1) != compute_dedup_signature(event2)


class TestAggregateErrorGroups:
    def test_groups_by_fingerprint(self, sample_events, fingerprinter):
        for e in sample_events:
            e.category_id = "database" if "Database" in e.message else "auth"
            fingerprinter.fingerprint_event(e)
        groups = aggregate_error_groups(sample_events, fingerprinter, create_default_config())
        assert len(groups) >= 2

    def test_group_count(self, sample_events, fingerprinter):
        for e in sample_events:
            e.category_id = "database" if "Database" in e.message else "auth"
            fingerprinter.fingerprint_event(e)
        groups = aggregate_error_groups(sample_events, fingerprinter, create_default_config())
        db_group = [g for g in groups if g.exception_type == "ConnectionError"]
        assert len(db_group) == 1
        assert db_group[0].count == 3

    def test_group_services(self, sample_events, fingerprinter):
        for e in sample_events:
            e.category_id = "database" if "Database" in e.message else "auth"
            fingerprinter.fingerprint_event(e)
        groups = aggregate_error_groups(sample_events, fingerprinter, create_default_config())
        assert all("test-service" in g.services for g in groups)

    def test_group_first_last_seen(self, sample_events, fingerprinter):
        for e in sample_events:
            e.category_id = "database" if "Database" in e.message else "auth"
            e.timestamp = datetime(2026, 1, 1, 12, e.event_id * 5, 0, tzinfo=UTC)
            fingerprinter.fingerprint_event(e)
        groups = aggregate_error_groups(sample_events, fingerprinter, create_default_config())
        db_group = [g for g in groups if g.exception_type == "ConnectionError"][0]
        assert db_group.first_seen <= db_group.last_seen

    def test_top_n_limits_results(self, sample_events, fingerprinter):
        for e in sample_events:
            e.category_id = "database" if "Database" in e.message else "auth"
            fingerprinter.fingerprint_event(e)
        groups = aggregate_error_groups(sample_events, fingerprinter, create_default_config(), top_n=1)
        assert len(groups) == 1

    def test_sort_by_count(self, sample_events, fingerprinter):
        for e in sample_events:
            e.category_id = "database" if "Database" in e.message else "auth"
            fingerprinter.fingerprint_event(e)
        groups = aggregate_error_groups(sample_events, fingerprinter, create_default_config(), sort_by="count")
        counts = [g.count for g in groups]
        assert counts == sorted(counts, reverse=True)

    def test_empty_events(self, fingerprinter):
        groups = aggregate_error_groups([], fingerprinter, create_default_config())
        assert len(groups) == 0


class TestBuildHighPriorityFindings:
    def test_findings_structure(self, sample_events, fingerprinter):
        for e in sample_events:
            e.category_id = "database" if "Database" in e.message else "auth"
            fingerprinter.fingerprint_event(e)
        groups = aggregate_error_groups(sample_events, fingerprinter, create_default_config())
        findings = build_high_priority_findings(groups, [], total_error_events=5)
        assert isinstance(findings, list)
        for f in findings:
            assert "priority" in f
            assert "title" in f
            assert "impact" in f

    def test_findings_with_alerts(self, sample_events, fingerprinter):
        for e in sample_events:
            e.category_id = "database" if "Database" in e.message else "auth"
            fingerprinter.fingerprint_event(e)
        groups = aggregate_error_groups(sample_events, fingerprinter, create_default_config())
        from log_analyzer.models import AnomalyAlert
        alerts = [
            AnomalyAlert(
                alert_id="a1",
                window_start=datetime(2026, 1, 1, tzinfo=UTC),
                window_end=datetime(2026, 1, 1, 5, tzinfo=UTC),
                window_size="5min",
                alert_type="confirmed_threshold",
                severity_label="CRITICAL",
                observed_count=50,
                baseline_mean=5.0,
                baseline_median=4.0,
                baseline_mad=2.0,
                ratio_over_baseline=10.0,
                modified_z_score=5.0,
                threshold_limit=25,
                explanation="Spike",
            )
        ]
        findings = build_high_priority_findings(groups, alerts, total_error_events=5)
        assert len(findings) > 0
