"""Tests for deterministic rule-based classification, fingerprinting, and TOML config validation."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest

from log_analyzer.classifier import FailureClassifier
from log_analyzer.config import (
    AnalyzerConfig,
    ConfigValidationError,
    load_config,
    parse_and_validate_config_dict,
)
from log_analyzer.fingerprinter import ErrorFingerprinter
from log_analyzer.models import LogEvent


def _make_event(
    message: str,
    severity: str = "ERROR",
    exception_type: str | None = None,
    error_code: str | None = None,
) -> LogEvent:
    return LogEvent(
        event_id=1,
        timestamp=datetime(2026, 10, 16, 10, 0, 0, tzinfo=UTC),
        raw_timestamp="2026-10-16T10:00:00Z",
        timezone_name="UTC",
        severity=severity,
        service="test-svc",
        logger="test.mod",
        message=message,
        exception_type=exception_type,
        error_code=error_code,
    )


def test_all_ten_failure_categories_classified_correctly(
    default_config: AnalyzerConfig,
) -> None:
    classifier = FailureClassifier(default_config)

    cases = [
        ("psycopg2.OperationalError: database connection refused on port 5432", "database_error"),
        ("ReadTimeout: Upstream request timed out after 5000ms", "timeout_error"),
        ("Authentication failed: invalid token signature HTTP 401", "auth_error"),
        ("ConnectionResetError: [Errno 104] ECONNRESET Connection reset by peer", "network_error"),
        ("PermissionError: [Errno 13] EACCES: Permission denied '/etc/secret'", "filesystem_error"),
        ("MemoryError: ENOMEM cannot allocate memory for worker buffer", "resource_exhaustion"),
        ("Webhook delivery failed with HTTP 502 Bad Gateway", "api_http_error"),
        (
            "ConfigurationError: Missing required environment variable DB_HOST",
            "configuration_error",
        ),
        ("Unhandled exception: KeyError 'customer_tier'", "application_exception"),
        ("Mysterious subsystem glitch without known pattern", "uncategorized_error"),
    ]

    for msg, expected_cat_id in cases:
        ev = _make_event(msg, severity="ERROR")
        classifier.classify(ev)
        assert ev.category_id == expected_cat_id, f"Failed for message: {msg}"
        assert ev.investigation_hint != ""

    # Normal INFO event
    info_ev = _make_event("User profile loaded in 12ms", severity="INFO")
    classifier.classify(info_ev)
    assert info_ev.category_id == "normal_operation"


def test_fingerprinter_masks_variables_without_merging_distinct_errors(
    default_config: AnalyzerConfig,
) -> None:
    classifier = FailureClassifier(default_config)
    fp = ErrorFingerprinter(default_config.fingerprinting)

    # Same underlying error with changing UUID, req_id, IP, hex address, duration, and numbers
    ev1 = _make_event(
        "[req-1001] Failed to fetch order 550e8400-e29b-41d4-a716-446655440000 from 10.0.1.12:8080 "
        "after 1520ms at 0x7fff5fbff8c0 (attempt 1 of 3)",
        exception_type="TimeoutError",
        error_code="ETIMEDOUT",
    )
    ev2 = _make_event(
        "[req-9999] Failed to fetch order 123e4567-e89b-12d3-a456-426614174000 from 192.168.2.55:8080 "
        "after 4980ms at 0x7fff11223344 (attempt 3 of 5)",
        exception_type="TimeoutError",
        error_code="ETIMEDOUT",
    )
    classifier.classify(ev1)
    classifier.classify(ev2)
    fp.fingerprint_event(ev1)
    fp.fingerprint_event(ev2)

    assert ev1.fingerprint == ev2.fingerprint
    assert ev1.fingerprint_template == ev2.fingerprint_template
    assert "<UUID>" in ev1.fingerprint_template
    assert "<REQ_ID>" in ev1.fingerprint_template
    assert "<IP>" in ev1.fingerprint_template
    assert "<HEX_ADDR>" in ev1.fingerprint_template
    assert "<DURATION>" in ev1.fingerprint_template
    assert ev1.fingerprint_confidence == "high"

    # Distinct HTTP status codes (502 vs 503) must NOT merge into the same fingerprint
    ev_502 = _make_event("Upstream gateway returned HTTP 502 error", error_code="HTTP_502")
    ev_503 = _make_event("Upstream gateway returned HTTP 503 error", error_code="HTTP_503")
    classifier.classify(ev_502)
    classifier.classify(ev_503)
    fp.fingerprint_event(ev_502)
    fp.fingerprint_event(ev_503)
    assert ev_502.fingerprint != ev_503.fingerprint


def test_config_validation_catches_invalid_rules_and_syntax(tmp_path: Path) -> None:
    # Valid example config loads cleanly
    cfg = load_config("config.example.toml")
    assert len(cfg.classification_rules) >= 9

    # Non-existent file raises ConfigValidationError
    with pytest.raises(ConfigValidationError):
        load_config(tmp_path / "missing.toml")

    # Invalid regex and invalid threshold in config dict
    bad_dict = {
        "general": {"default_format": "invalid_fmt", "top_n": -5},
        "custom_parser": {"enabled": True, "pattern": "([unclosed"},
        "anomaly_detection": {"time_window": "99h", "absolute_threshold": 0},
    }
    with pytest.raises(ConfigValidationError) as exc_info:
        parse_and_validate_config_dict(bad_dict)

    err_text = str(exc_info.value)
    assert "general.default_format" in err_text
    assert "general.top_n" in err_text
    assert "custom_parser.pattern" in err_text
    assert "anomaly_detection.time_window" in err_text
    assert "anomaly_detection.absolute_threshold" in err_text

    # Test unknown section and invalid rule structures
    bad_rules_dict = {
        "unknown_sec": {},
        "general": {
            "encoding": "",
            "recursive": "not_bool",
            "deduplicate_rotated": "not_bool",
            "failure_severity_threshold": "NOT_A_SEV",
        },
        "filtering": {"exclude_patterns": ["[bad_regex"]},
        "security": {
            "enable_redaction": "not_bool",
            "csv_formula_protection": "not_bool",
            "redaction_rules": [{"name": "r1", "pattern": ""}],
        },
        "fingerprinting": {
            "mask_uuids": "not_bool",
            "custom_masks": [{"name": "m1", "pattern": ""}],
        },
        "anomaly_detection": {"ratio_threshold": -1.0},
        "classification": {
            "rules": [
                {
                    "id": "",
                    "name": "",
                    "priority": "bad",
                    "patterns": [],
                    "severity_override": "INVALID_SEV",
                }
            ]
        },
    }
    with pytest.raises(ConfigValidationError) as exc_info2:
        parse_and_validate_config_dict(bad_rules_dict)
    err_text2 = str(exc_info2.value)
    assert "unknown_sec" in err_text2
    assert "classification.rules[0]" in err_text2
