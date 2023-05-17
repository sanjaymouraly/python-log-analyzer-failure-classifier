"""Deterministic, explainable rule-based failure classifier."""

from __future__ import annotations

import re
from dataclasses import dataclass

from log_analyzer.config import AnalyzerConfig, ClassificationRuleConfig
from log_analyzer.models import LogEvent, severity_rank


@dataclass
class CompiledClassificationRule:
    """Pre-compiled classification rule for fast evaluation."""

    config: ClassificationRuleConfig
    compiled_patterns: list[tuple[str, re.Pattern[str]]]


class FailureClassifier:
    """Classifies normalized LogEvents into deterministic failure categories."""

    def __init__(self, config: AnalyzerConfig) -> None:
        self.failure_threshold = config.failure_severity_threshold
        self.rules: list[CompiledClassificationRule] = []
        for rule_cfg in sorted(config.classification_rules, key=lambda r: r.priority):
            compiled = [(pat, re.compile(pat)) for pat in rule_cfg.patterns]
            self.rules.append(
                CompiledClassificationRule(config=rule_cfg, compiled_patterns=compiled)
            )

    def classify(self, event: LogEvent) -> LogEvent:
        """Classify a LogEvent in place and return it."""
        is_failure_level = severity_rank(event.severity) >= severity_rank(self.failure_threshold)
        has_exception = bool(event.exception_type or event.traceback)

        if not is_failure_level and not has_exception and event.severity != "UNKNOWN":
            event.category_id = "normal_operation"
            event.category_name = "Normal Operation"
            event.matched_rule = "severity_below_failure_threshold"
            event.investigation_hint = ""
            return event

        # Build candidate text for matching
        parts = [event.message]
        if event.exception_type:
            parts.append(event.exception_type)
        if event.error_code:
            parts.append(event.error_code)
        if event.logger:
            parts.append(event.logger)
        if event.traceback:
            # Include traceback tail (last 5 lines) for accurate exception classification
            tb_lines = event.traceback.splitlines()
            parts.append("\n".join(tb_lines[-5:]))
        candidate_text = "\n".join(parts)

        for compiled_rule in self.rules:
            for raw_pat, regex in compiled_rule.compiled_patterns:
                if regex.search(candidate_text):
                    event.category_id = compiled_rule.config.id
                    event.category_name = compiled_rule.config.name
                    event.matched_rule = (
                        f"{compiled_rule.config.id} (priority={compiled_rule.config.priority})"
                        f" matched /{raw_pat[:60]}/"
                    )
                    event.investigation_hint = compiled_rule.config.investigation_hint
                    if compiled_rule.config.severity_override:
                        event.severity = compiled_rule.config.severity_override
                    return event

        if is_failure_level or has_exception or event.severity == "UNKNOWN":
            event.category_id = "uncategorized_error"
            event.category_name = "Uncategorized Errors"
            event.matched_rule = "fallback: no classification rule matched"
            event.investigation_hint = (
                "Inspect the full log message, service context, and surrounding events "
                "around this timestamp to determine the failure cause."
            )
        else:
            event.category_id = "normal_operation"
            event.category_name = "Normal Operation"
            event.matched_rule = "severity_below_threshold"
            event.investigation_hint = ""

        return event
