"""Unit tests for rule-based failure classification."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from log_analyzer.classifier import FailureClassifier
from log_analyzer.config import (
    ClassificationRuleConfig,
    create_default_config,
)
from log_analyzer.models import LogEvent


def _make_event(**kwargs) -> LogEvent:
    defaults = {
        "event_id": 1,
        "timestamp": datetime(2026, 1, 1, tzinfo=UTC),
        "raw_timestamp": "2026-01-01T00:00:00+00:00",
        "timezone_name": "UTC",
        "severity": "ERROR",
        "service": "test-service",
        "logger": "test.logger",
        "message": "Test error message",
    }
    defaults.update(kwargs)
    return LogEvent(**defaults)


@pytest.fixture
def classifier():
    return FailureClassifier(create_default_config())


class TestDefaultClassification:
    def test_database_error(self, classifier):
        event = _make_event(message="Database connection failed: could not reach host")
        result = classifier.classify(event)
        assert result.category_id == "database_error"
        assert result.category_name == "Database Errors"

    def test_timeout_error(self, classifier):
        event = _make_event(message="Request timeout after 30 seconds")
        result = classifier.classify(event)
        assert result.category_id == "timeout_error"

    def test_auth_error(self, classifier):
        event = _make_event(message="Authentication failed: invalid credentials")
        result = classifier.classify(event)
        assert result.category_id == "auth_error"

    def test_network_error(self, classifier):
        event = _make_event(message="Network unreachable: connection refused")
        result = classifier.classify(event)
        assert result.category_id == "network_error"

    def test_filesystem_error(self, classifier):
        event = _make_event(message="FileNotFoundError: /tmp/data.txt permission denied")
        result = classifier.classify(event)
        assert result.category_id == "filesystem_error"

    def test_resource_error(self, classifier):
        event = _make_event(message="MemoryError: out of memory")
        result = classifier.classify(event)
        assert result.category_id == "resource_exhaustion"

    def test_api_http_error(self, classifier):
        event = _make_event(message="HTTP 503 Service Unavailable from API")
        result = classifier.classify(event)
        assert result.category_id == "api_http_error"

    def test_config_error(self, classifier):
        event = _make_event(message="ConfigurationError: missing required setting")
        result = classifier.classify(event)
        assert result.category_id == "configuration_error"

    def test_application_error(self, classifier):
        event = _make_event(message="ValueError: invalid input in processing")
        result = classifier.classify(event)
        assert result.category_id == "application_exception"

    def test_uncategorized_error(self, classifier):
        event = _make_event(message="Something went wrong but we don't know what category")
        result = classifier.classify(event)
        assert result.category_id == "uncategorized_error"

    def test_normal_operation_info(self, classifier):
        event = _make_event(severity="INFO", message="Server started successfully")
        result = classifier.classify(event)
        assert result.category_id == "normal_operation"

    def test_normal_operation_debug(self, classifier):
        event = _make_event(severity="DEBUG", message="Entering function process_data")
        result = classifier.classify(event)
        assert result.category_id == "normal_operation"

    def test_warning_is_normal_operation(self, classifier):
        event = _make_event(severity="WARNING", message="Disk space running low")
        result = classifier.classify(event)
        assert result.category_id == "normal_operation"


class TestClassificationMetadata:
    def test_matched_rule_set(self, classifier):
        event = _make_event(message="Database connection failed")
        result = classifier.classify(event)
        assert result.matched_rule != ""

    def test_investigation_hint_set(self, classifier):
        event = _make_event(message="Database connection failed")
        result = classifier.classify(event)
        assert result.investigation_hint != ""

    def test_severity_override(self):
        config = create_default_config()
        config.classification_rules = [
            ClassificationRuleConfig(
                id="test_override",
                name="Test Override",
                priority=1,
                patterns=["special error"],
                investigation_hint="Check special handling",
                severity_override="CRITICAL",
            )
        ]
        classifier = FailureClassifier(config)
        event = _make_event(severity="ERROR", message="This is a special error condition")
        result = classifier.classify(event)
        assert result.severity == "CRITICAL"

    def test_priority_ordering(self):
        config = create_default_config()
        config.classification_rules = [
            ClassificationRuleConfig(
                id="low_priority",
                name="Low Priority",
                priority=100,
                patterns=["error"],
                investigation_hint="Low priority hint",
            ),
            ClassificationRuleConfig(
                id="high_priority",
                name="High Priority",
                priority=1,
                patterns=["error"],
                investigation_hint="High priority hint",
            ),
        ]
        classifier = FailureClassifier(config)
        event = _make_event(message="error occurred")
        result = classifier.classify(event)
        assert "high_priority" in result.matched_rule

    def test_classify_mutates_in_place(self, classifier):
        event = _make_event(message="Database connection failed")
        original_id = id(event)
        result = classifier.classify(event)
        assert id(result) == original_id
        assert result.category_id == "database_error"


class TestCustomRules:
    def test_custom_rule_classification(self):
        config = create_default_config()
        config.classification_rules = [
            ClassificationRuleConfig(
                id="custom_category",
                name="Custom Category",
                priority=1,
                patterns=["myapp specific failure"],
                investigation_hint="Check custom app logs",
            )
        ]
        classifier = FailureClassifier(config)
        event = _make_event(message="myapp specific failure in module")
        result = classifier.classify(event)
        assert result.category_id == "custom_category"
        assert result.category_name == "Custom Category"

    def test_custom_rule_with_severity_override(self):
        config = create_default_config()
        config.classification_rules = [
            ClassificationRuleConfig(
                id="custom_critical",
                name="Custom Critical",
                priority=1,
                patterns=["critical app error"],
                investigation_hint="Urgent",
                severity_override="CRITICAL",
            )
        ]
        classifier = FailureClassifier(config)
        event = _make_event(severity="ERROR", message="critical app error detected")
        result = classifier.classify(event)
        assert result.severity == "CRITICAL"
        assert result.category_id == "custom_critical"
