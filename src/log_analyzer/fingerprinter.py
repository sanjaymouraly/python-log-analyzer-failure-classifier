"""Configurable error fingerprinting and variable masking for recurring failure detection."""

from __future__ import annotations

import hashlib
import re

from log_analyzer.config import FingerprintingConfig
from log_analyzer.models import LogEvent

UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b"
)
REQ_ID_INLINE_RE = re.compile(
    r"(?i)(?:\[(?:req|corr|trace|tx)-[A-Za-z0-9_-]+\]|"
    r"\b(?:req(?:uest)?[_-]?id|corr(?:elation)?[_-]?id|trace[_-]?id|tx[_-]?id)\s*[=:]\s*['\"]?[A-Za-z0-9_-]+['\"]?|"
    r"\b(?:req|corr|trace|tx)-[A-Za-z0-9_-]{4,}\b)"
)
TIMESTAMP_INLINE_RE = re.compile(
    r"\b\d{4}[-/]\d{2}[-/]\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b"
)
HEX_ADDR_RE = re.compile(r"\b0x[0-9a-fA-F]{4,16}\b")
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?\b")
DURATION_RE = re.compile(
    r"\b\d+(?:\.\d+)?\s*(?:ms|msec|s|sec|seconds|us|ns|kb|mb|gb|tb|%)\b",
    re.IGNORECASE,
)
# Protect HTTP status codes and standard error codes from generic number masking
PROTECTED_CODE_RE = re.compile(
    r"\b(?:HTTP(?:/\d\.\d)?\s+[1-5]\d{2}|HTTP_[1-5]\d{2}|ORA-\d{5}|AH\d{5}|SQLSTATE\[?[0-9A-Z]{5}\]?|ERR_[A-Z0-9_]+|port\s+\d{2,5}|v\d+|UTF-8|ISO-8601|SHA-256)\b",
    re.IGNORECASE,
)
STANDALONE_NUM_RE = re.compile(r"(?<![A-Za-z0-9<>])\d+(?:\.\d+)?(?![A-Za-z0-9<>])")
WHITESPACE_RE = re.compile(r"\s+")


class ErrorFingerprinter:
    """Computes deterministic error fingerprints while masking dynamic values."""

    def __init__(self, config: FingerprintingConfig) -> None:
        self.config = config
        self.custom_masks: list[tuple[re.Pattern[str], str]] = [
            (re.compile(m.pattern), m.placeholder) for m in config.custom_masks
        ]

    def normalize_message(self, message: str) -> str:
        """Mask variable tokens in a log message to produce a stable template."""
        if not message:
            return "<EMPTY_MESSAGE>"

        text = message.strip()

        # 1. Apply user custom masks first
        for regex, placeholder in self.custom_masks:
            text = regex.sub(placeholder, text)

        # 2. Protect error codes / HTTP status / standard service ports before number masking
        protected_tokens: dict[str, str] = {}

        def _stash_protected(match: re.Match[str]) -> str:
            idx = len(protected_tokens)
            key = f"__PROT{idx:04d}__"
            protected_tokens[key] = match.group(0)
            return key

        text = PROTECTED_CODE_RE.sub(_stash_protected, text)

        # 3. Mask UUIDs
        if self.config.mask_uuids:
            text = UUID_RE.sub("<UUID>", text)

        # 4. Mask request / correlation / trace IDs
        if self.config.mask_request_ids:
            text = REQ_ID_INLINE_RE.sub("<REQ_ID>", text)

        # 5. Mask inline timestamps
        if self.config.mask_timestamps:
            text = TIMESTAMP_INLINE_RE.sub("<TIMESTAMP>", text)

        # 6. Mask hex memory addresses
        if self.config.mask_hex_addresses:
            text = HEX_ADDR_RE.sub("<HEX_ADDR>", text)

        # 7. Mask IPv4 addresses
        if self.config.mask_ip_addresses:
            text = IPV4_RE.sub("<IP>", text)

        # 8. Mask durations and metrics
        if self.config.mask_durations:
            text = DURATION_RE.sub("<DURATION>", text)

        # 9. Mask standalone numeric identifiers
        if self.config.mask_numbers:
            text = STANDALONE_NUM_RE.sub("<NUM>", text)

        # Restore protected codes
        for key, original in protected_tokens.items():
            text = text.replace(key, original)

        return WHITESPACE_RE.sub(" ", text).strip()

    def assess_confidence(
        self, template: str, exception_type: str | None, error_code: str | None
    ) -> tuple[str, str]:
        """Evaluate grouping confidence based on template specificity and metadata."""
        static_words = [
            w
            for w in re.split(r"\s+", template)
            if w and not (w.startswith("<") and w.endswith(">")) and not (w.startswith("[REDACTED"))
        ]
        if (exception_type or error_code) and len(static_words) >= 3:
            return (
                "high",
                "High confidence: grouped by specific exception/error code and multi-token template.",
            )
        if len(static_words) >= 4:
            return (
                "high",
                "High confidence: distinct structural message template with sufficient static context.",
            )
        if len(static_words) >= 2:
            return (
                "medium",
                "Medium confidence: short message template; verify source locations if multiple callers log similar phrases.",
            )
        return (
            "low",
            "Low confidence: message contains mostly dynamic tokens; distinct failures with generic wording may be grouped together.",
        )

    def fingerprint_event(self, event: LogEvent) -> LogEvent:
        """Compute and attach fingerprint, template, and confidence to a LogEvent."""
        template = self.normalize_message(event.message)
        confidence, _note = self.assess_confidence(template, event.exception_type, event.error_code)

        # Build composite hash key so unrelated categories/exceptions/codes never collide
        hash_payload = "|".join(
            [
                event.category_id,
                (event.exception_type or "").lower(),
                (event.error_code or "").lower(),
                template.lower(),
            ]
        )
        digest = hashlib.sha256(hash_payload.encode("utf-8")).hexdigest()[:12]

        event.fingerprint = digest
        event.fingerprint_template = template
        event.fingerprint_confidence = confidence
        return event
