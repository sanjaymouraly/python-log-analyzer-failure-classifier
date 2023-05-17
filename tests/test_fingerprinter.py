"""Unit tests for error fingerprinting and variable masking."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from log_analyzer.config import FingerprintingConfig, create_default_config
from log_analyzer.fingerprinter import ErrorFingerprinter
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
def fingerprinter():
    return ErrorFingerprinter(create_default_config().fingerprinting)


class TestNormalizeMessage:
    def test_empty_message(self, fingerprinter):
        assert fingerprinter.normalize_message("") == "<EMPTY_MESSAGE>"

    def test_none_message(self, fingerprinter):
        assert fingerprinter.normalize_message(None) == "<EMPTY_MESSAGE>"

    def test_uuid_masking(self, fingerprinter):
        msg = "Request failed for user 550e8400-e29b-41d4-a716-446655440000"
        result = fingerprinter.normalize_message(msg)
        assert "550e8400-e29b-41d4-a716-446655440000" not in result
        assert "<UUID>" in result

    def test_request_id_masking(self, fingerprinter):
        msg = "Request [req-abc-123-def] failed"
        result = fingerprinter.normalize_message(msg)
        assert "abc-123-def" not in result
        assert "<REQ_ID>" in result

    def test_request_id_key_value_masking(self, fingerprinter):
        msg = "Request failed req_id=xyz789"
        result = fingerprinter.normalize_message(msg)
        assert "xyz789" not in result
        assert "<REQ_ID>" in result

    def test_timestamp_masking(self, fingerprinter):
        msg = "Error at 2026-01-01T12:00:00Z in module"
        result = fingerprinter.normalize_message(msg)
        assert "2026-01-01T12:00:00" not in result
        assert "<TIMESTAMP>" in result

    def test_hex_address_masking(self, fingerprinter):
        msg = "Crash at 0x7fff5fbff8c0 in thread"
        result = fingerprinter.normalize_message(msg)
        assert "0x7fff5fbff8c0" not in result
        assert "<HEX_ADDR>" in result

    def test_ip_address_masking(self, fingerprinter):
        msg = "Connection from 192.168.1.100 failed"
        result = fingerprinter.normalize_message(msg)
        assert "192.168.1.100" not in result
        assert "<IP>" in result

    def test_duration_masking(self, fingerprinter):
        msg = "Request took 1500ms to complete"
        result = fingerprinter.normalize_message(msg)
        assert "1500ms" not in result
        assert "<DURATION>" in result

    def test_number_masking(self, fingerprinter):
        msg = "Error code 42 occurred in module"
        result = fingerprinter.normalize_message(msg)
        assert "42" not in result
        assert "<NUM>" in result

    def test_whitespace_normalization(self, fingerprinter):
        msg = "Error    with   multiple    spaces"
        result = fingerprinter.normalize_message(msg)
        assert "  " not in result

    def test_protected_codes_preserved(self, fingerprinter):
        msg = "HTTP 503 Service Unavailable on port 443"
        result = fingerprinter.normalize_message(msg)
        assert "503" in result
        assert "443" in result

    def test_custom_mask(self):
        config = FingerprintingConfig(
            mask_uuids=True,
            mask_request_ids=True,
            mask_timestamps=True,
            mask_ip_addresses=True,
            mask_hex_addresses=True,
            mask_numbers=True,
            mask_durations=True,
            custom_masks=[],
        )
        fp = ErrorFingerprinter(config)
        msg = "Error with custom secret value"
        result = fp.normalize_message(msg)
        assert "custom" in result

    def test_many_protected_tokens(self, fingerprinter):
        """Test that stashing more than 676 protected tokens doesn't crash."""
        tokens = " ".join(f"ERR_{i:04d}" for i in range(700))
        msg = f"Multiple errors: {tokens}"
        result = fingerprinter.normalize_message(msg)
        assert "ERR_0000" in result
        assert "ERR_0699" in result


class TestAssessConfidence:
    def test_high_confidence_with_exception_and_code(self, fingerprinter):
        template = "Database connection failed for host <IP> port <NUM>"
        confidence, note = fingerprinter.assess_confidence(template, "ConnectionError", "ERR_001")
        assert confidence == "high"
        assert "High confidence" in note

    def test_high_confidence_with_static_words(self, fingerprinter):
        template = "Specific error message with many static words"
        confidence, note = fingerprinter.assess_confidence(template, None, None)
        assert confidence == "high"

    def test_medium_confidence(self, fingerprinter):
        template = "Short error"
        confidence, note = fingerprinter.assess_confidence(template, None, None)
        assert confidence == "medium"

    def test_low_confidence(self, fingerprinter):
        template = "<NUM>"
        confidence, note = fingerprinter.assess_confidence(template, None, None)
        assert confidence == "low"


class TestFingerprintEvent:
    def test_fingerprint_deterministic(self, fingerprinter):
        event1 = _make_event(message="Connection failed to 192.168.1.1")
        event2 = _make_event(message="Connection failed to 10.0.0.1")
        fingerprinter.fingerprint_event(event1)
        fingerprinter.fingerprint_event(event2)
        assert event1.fingerprint == event2.fingerprint

    def test_fingerprint_differs_for_different_messages(self, fingerprinter):
        event1 = _make_event(message="Connection failed to host")
        event2 = _make_event(message="Authentication failed for user")
        fingerprinter.fingerprint_event(event1)
        fingerprinter.fingerprint_event(event2)
        assert event1.fingerprint != event2.fingerprint

    def test_fingerprint_length(self, fingerprinter):
        event = _make_event(message="Test error")
        fingerprinter.fingerprint_event(event)
        assert len(event.fingerprint) == 12

    def test_template_set(self, fingerprinter):
        event = _make_event(message="Error in module <NUM>")
        fingerprinter.fingerprint_event(event)
        assert event.fingerprint_template != ""

    def test_confidence_set(self, fingerprinter):
        event = _make_event(message="Database connection failed", exception_type="ConnectionError")
        fingerprinter.fingerprint_event(event)
        assert event.fingerprint_confidence in ("high", "medium", "low")

    def test_same_message_same_fingerprint(self, fingerprinter):
        event1 = _make_event(message="Identical error message")
        event2 = _make_event(message="Identical error message")
        fingerprinter.fingerprint_event(event1)
        fingerprinter.fingerprint_event(event2)
        assert event1.fingerprint == event2.fingerprint
