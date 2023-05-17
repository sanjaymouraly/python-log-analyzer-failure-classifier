"""Unit tests for configuration loading, validation, and TOML parsing."""

from __future__ import annotations

from pathlib import Path

import pytest

from log_analyzer.config import (
    VALID_FORMATS,
    VALID_SEVERITIES,
    VALID_TIME_WINDOWS,
    AnomalyConfig,
    ConfigValidationError,
    FingerprintingConfig,
    SecurityConfig,
    create_default_config,
    default_classification_rules,
    default_redaction_rules,
    load_config,
    parse_and_validate_config_dict,
)


class TestCreateDefaultConfig:
    def test_returns_analyzer_config(self):
        cfg = create_default_config()
        assert cfg.encoding == "utf-8"
        assert cfg.recursive is True
        assert cfg.default_format == "auto"
        assert cfg.deduplicate_rotated is True
        assert cfg.top_n == 15
        assert cfg.failure_severity_threshold == "ERROR"

    def test_nested_configs(self):
        cfg = create_default_config()
        assert isinstance(cfg.security, SecurityConfig)
        assert isinstance(cfg.fingerprinting, FingerprintingConfig)
        assert isinstance(cfg.anomaly_detection, AnomalyConfig)
        assert cfg.security.enable_redaction is True
        assert cfg.security.csv_formula_protection is True

    def test_default_classification_rules_nonempty(self):
        rules = default_classification_rules()
        assert len(rules) >= 5
        ids = [r.id for r in rules]
        assert "database_error" in ids
        assert "timeout_error" in ids
        assert "auth_error" in ids

    def test_default_redaction_rules_nonempty(self):
        rules = default_redaction_rules()
        assert len(rules) >= 3
        names = [r.name for r in rules]
        assert any("jwt" in n.lower() or "token" in n.lower() for n in names)


class TestLoadConfig:
    def test_none_returns_defaults(self):
        cfg = load_config(None)
        assert cfg.encoding == "utf-8"

    def test_loads_toml_file(self, tmp_path: Path):
        config_file = tmp_path / "test.toml"
        config_file.write_text(
            """
[general]
encoding = "latin-1"
top_n = 25

[anomaly_detection]
time_window = "1h"
absolute_threshold = 50
""",
            encoding="utf-8",
        )
        cfg = load_config(config_file)
        assert cfg.encoding == "latin-1"
        assert cfg.top_n == 25
        assert cfg.anomaly_detection.time_window == "1h"
        assert cfg.anomaly_detection.absolute_threshold == 50

    def test_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(ConfigValidationError, match="does not exist"):
            load_config(tmp_path / "nonexistent.toml")

    def test_invalid_toml_raises(self, tmp_path: Path):
        config_file = tmp_path / "bad.toml"
        config_file.write_text("this is not valid toml {{{", encoding="utf-8")
        with pytest.raises(ConfigValidationError, match="Invalid TOML"):
            load_config(config_file)

    def test_non_utf8_raises(self, tmp_path: Path):
        config_file = tmp_path / "binary.toml"
        config_file.write_bytes(b"\xff\xfe\x00\x00invalid")
        with pytest.raises(ConfigValidationError, match="UTF-8"):
            load_config(config_file)


class TestParseAndValidateConfigDict:
    def test_empty_dict_returns_defaults(self):
        cfg = parse_and_validate_config_dict({})
        assert cfg.encoding == "utf-8"

    def test_invalid_encoding(self):
        with pytest.raises(ConfigValidationError, match="encoding"):
            parse_and_validate_config_dict({"general": {"encoding": 123}})

    def test_invalid_top_n_type(self):
        with pytest.raises(ConfigValidationError, match="top_n"):
            parse_and_validate_config_dict({"general": {"top_n": "fifteen"}})

    def test_invalid_top_n_negative(self):
        with pytest.raises(ConfigValidationError, match="top_n"):
            parse_and_validate_config_dict({"general": {"top_n": -1}})

    def test_invalid_default_format(self):
        with pytest.raises(ConfigValidationError, match="default_format"):
            parse_and_validate_config_dict({"general": {"default_format": "yaml"}})

    def test_valid_default_format(self):
        for fmt in VALID_FORMATS:
            cfg = parse_and_validate_config_dict({"general": {"default_format": fmt}})
            assert cfg.default_format == fmt

    def test_invalid_time_window(self):
        with pytest.raises(ConfigValidationError, match="time_window"):
            parse_and_validate_config_dict({"anomaly_detection": {"time_window": "2min"}})

    def test_valid_time_windows(self):
        for window in VALID_TIME_WINDOWS:
            cfg = parse_and_validate_config_dict(
                {"anomaly_detection": {"time_window": window}}
            )
            assert cfg.anomaly_detection.time_window == window

    def test_invalid_absolute_threshold(self):
        with pytest.raises(ConfigValidationError, match="absolute_threshold"):
            parse_and_validate_config_dict({"anomaly_detection": {"absolute_threshold": -5}})

    def test_invalid_ratio_threshold(self):
        with pytest.raises(ConfigValidationError, match="ratio_threshold"):
            parse_and_validate_config_dict({"anomaly_detection": {"ratio_threshold": 0}})

    def test_invalid_mad_z_threshold(self):
        with pytest.raises(ConfigValidationError, match="mad_z_threshold"):
            parse_and_validate_config_dict({"anomaly_detection": {"mad_z_threshold": 0}})

    def test_invalid_min_spike_count(self):
        with pytest.raises(ConfigValidationError, match="min_spike_count"):
            parse_and_validate_config_dict({"anomaly_detection": {"min_spike_count": 0}})

    def test_invalid_min_history_buckets(self):
        with pytest.raises(ConfigValidationError, match="min_history_buckets"):
            parse_and_validate_config_dict({"anomaly_detection": {"min_history_buckets": 0}})

    def test_invalid_rolling_window_buckets(self):
        with pytest.raises(ConfigValidationError, match="rolling_window_buckets"):
            parse_and_validate_config_dict({"anomaly_detection": {"rolling_window_buckets": 0}})

    def test_invalid_failure_severity(self):
        with pytest.raises(ConfigValidationError, match="failure_severity_threshold"):
            parse_and_validate_config_dict({"general": {"failure_severity_threshold": "SEVERE"}})

    def test_valid_failure_severities(self):
        for sev in VALID_SEVERITIES:
            cfg = parse_and_validate_config_dict(
                {"general": {"failure_severity_threshold": sev}}
            )
            assert cfg.failure_severity_threshold == sev

    def test_invalid_exclude_patterns_type(self):
        with pytest.raises(ConfigValidationError, match="exclude_patterns"):
            parse_and_validate_config_dict({"filtering": {"exclude_patterns": "not-a-list"}})

    def test_invalid_exclude_pattern_regex(self):
        with pytest.raises(ConfigValidationError, match="exclude_patterns"):
            parse_and_validate_config_dict({"filtering": {"exclude_patterns": ["[invalid"]}})

    def test_valid_exclude_patterns(self):
        cfg = parse_and_validate_config_dict(
            {"filtering": {"exclude_patterns": ["DEBUG", "healthcheck"]}}
        )
        assert cfg.exclude_patterns == ["DEBUG", "healthcheck"]

    def test_invalid_custom_parser_pattern(self):
        with pytest.raises(ConfigValidationError, match="custom_parser"):
            parse_and_validate_config_dict(
                {"custom_parser": {"enabled": True, "pattern": "[bad"}}
            )

    def test_valid_custom_parser_pattern(self):
        cfg = parse_and_validate_config_dict(
            {
                "custom_parser": {
                    "enabled": True,
                    "pattern": r"^(?P<timestamp>\S+)\s+(?P<severity>\w+)\s+(?P<message>.*)$",
                }
            }
        )
        assert cfg.custom_parser_enabled is True
        assert cfg.custom_parser_pattern.startswith("^")

    def test_security_config_override(self):
        cfg = parse_and_validate_config_dict(
            {"security": {"enable_redaction": False, "csv_formula_protection": False}}
        )
        assert cfg.security.enable_redaction is False
        assert cfg.security.csv_formula_protection is False

    def test_fingerprinting_config_override(self):
        cfg = parse_and_validate_config_dict(
            {"fingerprinting": {"mask_uuids": False, "mask_numbers": False}}
        )
        assert cfg.fingerprinting.mask_uuids is False
        assert cfg.fingerprinting.mask_numbers is False

    def test_classification_rules_valid(self):
        cfg = parse_and_validate_config_dict(
            {
                "classification": {
                    "rules": [
                        {
                            "id": "custom_db",
                            "name": "Custom Database Errors",
                            "priority": 1,
                            "patterns": ["database.*error", "db.*fail"],
                            "investigation_hint": "Check DB",
                        }
                    ]
                }
            }
        )
        assert len(cfg.classification_rules) >= 1
        custom = [r for r in cfg.classification_rules if r.id == "custom_db"]
        assert len(custom) == 1
        assert custom[0].priority == 1

    def test_classification_rules_invalid_regex(self):
        with pytest.raises(ConfigValidationError, match="patterns"):
            parse_and_validate_config_dict(
                {
                    "classification": {
                        "rules": [
                            {
                                "id": "bad_rule",
                                "name": "Bad Rule",
                                "priority": 1,
                                "patterns": ["[invalid regex"],
                            }
                        ]
                    }
                }
            )

    def test_classification_rules_invalid_priority(self):
        with pytest.raises(ConfigValidationError, match="priority"):
            parse_and_validate_config_dict(
                {
                    "classification": {
                        "rules": [
                            {
                                "id": "bad_rule",
                                "name": "Bad Rule",
                                "priority": "high",
                                "patterns": ["error"],
                            }
                        ]
                    }
                }
            )

    def test_classification_rules_invalid_severity_override(self):
        with pytest.raises(ConfigValidationError, match="severity_override"):
            parse_and_validate_config_dict(
                {
                    "classification": {
                        "rules": [
                            {
                                "id": "bad_rule",
                                "name": "Bad Rule",
                                "priority": 1,
                                "patterns": ["error"],
                                "severity_override": "EXTREME",
                            }
                        ]
                    }
                }
            )

    def test_classification_rules_empty_list(self):
        with pytest.raises(ConfigValidationError, match="rules"):
            parse_and_validate_config_dict({"classification": {"rules": []}})

    def test_multiple_errors_accumulated(self):
        with pytest.raises(ConfigValidationError) as exc_info:
            parse_and_validate_config_dict(
                {
                    "general": {"encoding": 123, "top_n": -1},
                    "anomaly_detection": {"time_window": "bad"},
                }
            )
        assert len(exc_info.value.errors) >= 3

    def test_redaction_rules_override(self):
        cfg = parse_and_validate_config_dict(
            {
                "security": {
                    "redaction_rules": [
                        {"name": "custom_secret", "pattern": r"secret=\w+", "replacement": "[HIDDEN]"}
                    ]
                }
            }
        )
        assert len(cfg.security.redaction_rules) == 1
        assert cfg.security.redaction_rules[0].name == "custom_secret"

    def test_invalid_redaction_rule_missing_field(self):
        with pytest.raises(ConfigValidationError, match="redaction_rules"):
            parse_and_validate_config_dict(
                {"security": {"redaction_rules": [{"name": "incomplete"}]}}
            )

    def test_invalid_redaction_rule_bad_regex(self):
        with pytest.raises(ConfigValidationError, match="redaction_rules"):
            parse_and_validate_config_dict(
                {"security": {"redaction_rules": [{"name": "bad", "pattern": "[bad", "replacement": "x"}]}}
            )
