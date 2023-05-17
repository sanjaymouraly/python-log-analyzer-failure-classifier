"""Security utilities: secret/PII redaction, HTML escaping, and CSV formula injection protection."""

from __future__ import annotations

import html
import re
from typing import Any

from log_analyzer.config import SecurityConfig

CSV_DANGEROUS_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


class SecretRedactor:
    """Applies configurable regular-expression redaction rules to log messages and metadata."""

    def __init__(self, config: SecurityConfig) -> None:
        self.enabled = config.enable_redaction
        self.compiled_rules: list[tuple[str, re.Pattern[str], str]] = [
            (rule.name, re.compile(rule.pattern), rule.replacement)
            for rule in config.redaction_rules
        ]
        self.sensitive_key_pattern = re.compile(
            r"(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|authorization|cookie|credential)"
        )
        self.redactions_count: int = 0

    def redact_text(self, text: str | None) -> str:
        """Redact sensitive values in a string and increment the redaction counter."""
        if not text:
            return ""
        if not self.enabled:
            return text

        current = text
        for _name, pattern, replacement in self.compiled_rules:
            if pattern.search(current):
                current, count = pattern.subn(replacement, current)
                if count > 0:
                    self.redactions_count += count
        return current

    def redact_dict(self, data: dict[str, Any]) -> dict[str, Any]:
        """Recursively redact sensitive keys and string values in a dictionary."""
        if not self.enabled or not data:
            return dict(data)

        result: dict[str, Any] = {}
        for k, v in data.items():
            if self.sensitive_key_pattern.search(str(k)) and v is not None and v != "":
                self.redactions_count += 1
                result[k] = "[REDACTED_SECRET]"
            elif isinstance(v, str):
                result[k] = self.redact_text(v)
            elif isinstance(v, dict):
                result[k] = self.redact_dict(v)
            elif isinstance(v, list):
                result[k] = [
                    self.redact_text(item) if isinstance(item, str) else item for item in v
                ]
            else:
                result[k] = v
        return result


def sanitize_csv_cell(value: Any, enabled: bool = True) -> Any:
    """Prevent CSV formula injection (OWASP CWE-1236) in string cells."""
    if value is None:
        return ""
    if isinstance(value, (int, float, bool)):
        return value
    text = str(value)
    if not enabled or not text:
        return text
    stripped = text.lstrip()
    if stripped and stripped[0] in CSV_DANGEROUS_PREFIXES:
        return f"'{text}"
    return text


def safe_html(value: Any) -> str:
    """Safely escape any value for HTML rendering."""
    if value is None:
        return ""
    return html.escape(str(value), quote=True)
