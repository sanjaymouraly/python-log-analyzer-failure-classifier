"""Unit tests for secret redaction, CSV sanitization, and HTML escaping."""

from __future__ import annotations

import pytest

from log_analyzer.config import create_default_config
from log_analyzer.security import SecretRedactor, safe_html, sanitize_csv_cell


@pytest.fixture
def redactor():
    return SecretRedactor(create_default_config().security)


@pytest.fixture
def disabled_redactor():
    config = create_default_config()
    config.security.enable_redaction = False
    return SecretRedactor(config.security)


class TestSecretRedactor:
    def test_jwt_redaction(self, redactor):
        token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
        text = f"Authorization: Bearer {token}"
        result = redactor.redact_text(text)
        assert token not in result
        assert "REDACTED" in result

    def test_api_key_redaction(self, redactor):
        text = "api_key=sk_live_1234567890abcdef"
        result = redactor.redact_text(text)
        assert "sk_live_1234567890abcdef" not in result

    def test_password_redaction(self, redactor):
        text = "password=supersecret123"
        result = redactor.redact_text(text)
        assert "supersecret123" not in result

    def test_email_redaction(self, redactor):
        text = "Contact admin@example.com for support"
        result = redactor.redact_text(text)
        # Email should be masked
        assert "admin@example.com" not in result

    def test_aws_key_redaction(self, redactor):
        text = "aws_access_key_id=AKIAIOSFODNN7EXAMPLE"
        result = redactor.redact_text(text)
        assert "AKIAIOSFODNN7EXAMPLE" not in result

    def test_disabled_redaction(self, disabled_redactor):
        text = "password=secret123"
        result = disabled_redactor.redact_text(text)
        assert result == text

    def test_none_input(self, redactor):
        assert redactor.redact_text(None) == ""

    def test_empty_input(self, redactor):
        assert redactor.redact_text("") == ""

    def test_no_sensitive_data(self, redactor):
        text = "This is a normal log message without secrets"
        result = redactor.redact_text(text)
        assert result == text

    def test_redactions_count_increments(self, redactor):
        initial = redactor.redactions_count
        redactor.redact_text("password=secret")
        assert redactor.redactions_count > initial

    def test_multiple_redactions_in_one_text(self, redactor):
        text = "password=secret1 api_key=secret2 access_token=secret3"
        result = redactor.redact_text(text)
        assert "secret1" not in result
        assert "secret2" not in result
        assert "secret3" not in result


class TestRedactDict:
    def test_sensitive_keys_redacted(self, redactor):
        data = {"password": "secret123", "username": "admin"}
        result = redactor.redact_dict(data)
        assert result["password"] == "[REDACTED_SECRET]"
        assert result["username"] == "admin"

    def test_nested_dict(self, redactor):
        data = {"config": {"api_key": "secret", "host": "localhost"}}
        result = redactor.redact_dict(data)
        assert result["config"]["api_key"] == "[REDACTED_SECRET]"
        assert result["config"]["host"] == "localhost"

    def test_list_values_redacted(self, redactor):
        data = {"tokens": ["secret1", "secret2"], "names": ["alice", "bob"]}
        result = redactor.redact_dict(data)
        assert "secret1" not in str(result["tokens"])

    def test_non_string_values_preserved(self, redactor):
        data = {"count": 42, "enabled": True, "ratio": 3.14}
        result = redactor.redact_dict(data)
        assert result["count"] == 42
        assert result["enabled"] is True
        assert result["ratio"] == 3.14

    def test_disabled_redact_dict(self, disabled_redactor):
        data = {"password": "secret123"}
        result = disabled_redactor.redact_dict(data)
        assert result["password"] == "secret123"


class TestSanitizeCsvCell:
    def test_formula_equals(self):
        assert sanitize_csv_cell("=SUM(A1:A10)") == "'=SUM(A1:A10)"

    def test_formula_plus(self):
        assert sanitize_csv_cell("+cmd|'!A'") == "'+cmd|'!A'"

    def test_formula_minus(self):
        assert sanitize_csv_cell("-2+3") == "'-2+3"

    def test_formula_at(self):
        assert sanitize_csv_cell("@SUM(A1)") == "'@SUM(A1)"

    def test_formula_tab(self):
        assert sanitize_csv_cell("\t=command") == "'\t=command"

    def test_normal_string(self):
        assert sanitize_csv_cell("normal text") == "normal text"

    def test_none_returns_empty(self):
        assert sanitize_csv_cell(None) == ""

    def test_numeric_preserved(self):
        assert sanitize_csv_cell(42) == 42
        assert sanitize_csv_cell(3.14) == 3.14

    def test_bool_preserved(self):
        assert sanitize_csv_cell(True) is True

    def test_disabled(self):
        assert sanitize_csv_cell("=formula", enabled=False) == "=formula"

    def test_empty_string(self):
        assert sanitize_csv_cell("") == ""


class TestSafeHtml:
    def test_escapes_html_tags(self):
        assert safe_html("<script>alert('xss')</script>") == "&lt;script&gt;alert(&#x27;xss&#x27;)&lt;/script&gt;"

    def test_escapes_ampersand(self):
        assert safe_html("foo & bar") == "foo &amp; bar"

    def test_escapes_quotes(self):
        assert safe_html('He said "hello"') == "He said &quot;hello&quot;"

    def test_none_returns_empty(self):
        assert safe_html(None) == ""

    def test_normal_text(self):
        assert safe_html("Hello World") == "Hello World"

    def test_numeric(self):
        assert safe_html(42) == "42"
