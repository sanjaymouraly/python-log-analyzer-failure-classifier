"""Tests for secret redaction, CSV formula-injection protection, and HTML escaping."""

from __future__ import annotations

from log_analyzer.config import AnalyzerConfig
from log_analyzer.security import SecretRedactor, safe_html, sanitize_csv_cell


def test_secret_redactor_masks_all_sensitive_patterns(
    default_config: AnalyzerConfig,
) -> None:
    redactor = SecretRedactor(default_config.security)

    raw_msg = (
        "Failed connecting to postgres://admin:MyTopSecretPwd!@10.0.0.5:5432/db "
        "for user john.doe@company.io with api_key=sk_live_ABCDEF123456789 "
        "and AWS key AKIAIOSFODNN7EXAMPLE and header Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U "
        "and password=PlainPass123"
    )
    scrubbed = redactor.redact_text(raw_msg)

    assert "MyTopSecretPwd!" not in scrubbed
    assert "postgres://admin:[REDACTED_PASSWORD]@10.0.0.5:5432/db" in scrubbed
    assert "john.doe@company.io" not in scrubbed
    assert "[REDACTED_EMAIL]" in scrubbed
    assert "sk_live_ABCDEF123456789" not in scrubbed
    assert "[REDACTED_SECRET]" in scrubbed
    assert "AKIAIOSFODNN7EXAMPLE" not in scrubbed
    assert "[REDACTED_AWS_KEY]" in scrubbed
    assert "PlainPass123" not in scrubbed
    assert "password=[REDACTED_PASSWORD]" in scrubbed
    assert redactor.redactions_count >= 5

    # Test dict redaction
    raw_dict = {
        "client_secret": "super-secret-val",
        "nested": {"user_email": "alice@example.org", "safe_count": 42},
    }
    clean_dict = redactor.redact_dict(raw_dict)
    assert clean_dict["client_secret"] == "[REDACTED_SECRET]"
    assert clean_dict["nested"]["user_email"] == "[REDACTED_EMAIL]"
    assert clean_dict["nested"]["safe_count"] == 42


def test_csv_formula_injection_protection() -> None:
    assert sanitize_csv_cell("=cmd|' /C calc'!A0") == "'=cmd|' /C calc'!A0"
    assert sanitize_csv_cell("+SUM(A1:A10)") == "'+SUM(A1:A10)"
    assert sanitize_csv_cell("-2+3+cmd") == "'-2+3+cmd"
    assert sanitize_csv_cell("@IMPORTXML(...)") == "'@IMPORTXML(...)"
    assert sanitize_csv_cell("  =HYPERLINK(...)") == "'  =HYPERLINK(...)"
    # Numeric values and normal strings remain untouched
    assert sanitize_csv_cell(42) == 42
    assert sanitize_csv_cell(-3.14) == -3.14
    assert sanitize_csv_cell("Normal error message") == "Normal error message"


def test_safe_html_escaping() -> None:
    malicious = '<script>alert("xss")</script><img src=x onerror=alert(1)>'
    escaped = safe_html(malicious)
    assert "<script>" not in escaped
    assert "&lt;script&gt;" in escaped
    assert "&quot;xss&quot;" in escaped
