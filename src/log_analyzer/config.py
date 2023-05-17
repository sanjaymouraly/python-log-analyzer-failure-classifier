"""Configuration management and validation for Python Log Analyzer."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from log_analyzer.models import SEVERITY_RANKS

VALID_FORMATS = {"auto", "python", "iso", "jsonl", "syslog", "apache", "nginx", "custom"}
VALID_TIME_WINDOWS = {"1min", "5min", "15min", "1h", "1d"}
VALID_SEVERITIES = set(SEVERITY_RANKS.keys()) - {"UNKNOWN"}


class ConfigValidationError(Exception):
    """Raised when configuration file validation fails."""

    def __init__(self, errors: list[str]) -> None:
        self.errors = errors
        message = "Configuration validation failed:\n" + "\n".join(f"  - {e}" for e in errors)
        super().__init__(message)


@dataclass
class RedactionRuleConfig:
    """Configuration for a single sensitive data redaction rule."""

    name: str
    pattern: str
    replacement: str


@dataclass
class CustomMaskConfig:
    """Configuration for a custom fingerprinting mask."""

    name: str
    pattern: str
    placeholder: str


@dataclass
class ClassificationRuleConfig:
    """Configuration for a deterministic failure classification rule."""

    id: str
    name: str
    priority: int
    patterns: list[str]
    investigation_hint: str
    severity_override: str = ""


@dataclass
class AnomalyConfig:
    """Configuration for spike and statistical anomaly detection."""

    time_window: str = "5min"
    rolling_window_buckets: int = 6
    min_history_buckets: int = 6
    min_spike_count: int = 8
    absolute_threshold: int = 25
    ratio_threshold: float = 3.0
    mad_z_threshold: float = 3.5


@dataclass
class FingerprintingConfig:
    """Configuration for error message fingerprinting and variable masking."""

    mask_uuids: bool = True
    mask_request_ids: bool = True
    mask_timestamps: bool = True
    mask_ip_addresses: bool = True
    mask_hex_addresses: bool = True
    mask_numbers: bool = True
    mask_durations: bool = True
    custom_masks: list[CustomMaskConfig] = field(default_factory=list)


@dataclass
class SecurityConfig:
    """Configuration for redaction and export safety."""

    enable_redaction: bool = True
    csv_formula_protection: bool = True
    redaction_rules: list[RedactionRuleConfig] = field(default_factory=list)


@dataclass
class AnalyzerConfig:
    """Top-level configuration object for the log analyzer."""

    encoding: str = "utf-8"
    recursive: bool = True
    default_format: str = "auto"
    deduplicate_rotated: bool = True
    top_n: int = 15
    failure_severity_threshold: str = "ERROR"
    custom_parser_enabled: bool = False
    custom_parser_pattern: str = ""
    exclude_patterns: list[str] = field(default_factory=list)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    fingerprinting: FingerprintingConfig = field(default_factory=FingerprintingConfig)
    anomaly_detection: AnomalyConfig = field(default_factory=AnomalyConfig)
    classification_rules: list[ClassificationRuleConfig] = field(default_factory=list)


def default_redaction_rules() -> list[RedactionRuleConfig]:
    """Return built-in sensitive data redaction rules."""
    return [
        RedactionRuleConfig(
            name="jwt_token",
            pattern=r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b",
            replacement="[REDACTED_JWT]",
        ),
        RedactionRuleConfig(
            name="bearer_token",
            pattern=r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]+=*",
            replacement="Bearer [REDACTED_TOKEN]",
        ),
        RedactionRuleConfig(
            name="api_key_or_secret",
            pattern=r"""(?i)\b(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*["']?[A-Za-z0-9_\-./+=]{6,}["']?""",
            replacement="[REDACTED_SECRET]",
        ),
        RedactionRuleConfig(
            name="aws_access_key",
            pattern=r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b",
            replacement="[REDACTED_AWS_KEY]",
        ),
        RedactionRuleConfig(
            name="password_assignment",
            pattern=r"""(?i)\b(?:password|passwd|pwd|db_pass)\s*[:=]\s*["']?[^\s"',;)]+["']?""",
            replacement="password=[REDACTED_PASSWORD]",
        ),
        RedactionRuleConfig(
            name="uri_credentials",
            pattern=r"(?i)\b([a-z][a-z0-9+.-]*://[^/\s:@]+):([^@\s/]+)@",
            replacement=r"\1:[REDACTED_PASSWORD]@",
        ),
        RedactionRuleConfig(
            name="email_address",
            pattern=r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
            replacement="[REDACTED_EMAIL]",
        ),
    ]


def default_classification_rules() -> list[ClassificationRuleConfig]:
    """Return built-in deterministic error classification rules."""
    return [
        ClassificationRuleConfig(
            id="database_error",
            name="Database Errors",
            priority=10,
            patterns=[
                r"(?i)\b(?:psycopg2|sqlalchemy|sqlite3|pymysql|asyncpg|mongodb|redis)\b.*\b(?:error|exception|failed|refused|timeout|deadlock|locked)\b",
                r"(?i)\b(?:database|db)\b.*\b(?:error|failed|failure|connection refused|pool exhausted|deadlock|lock wait timeout|syntax error|operationalerror|integrityerror|interfaceerror|too many connections)\b",
                r"(?i)\b(?:SQLSTATE|ORA-\d{5}|OperationalError|IntegrityError|DatabaseError|DataError|ProgrammingError)\b",
                r"(?i)\bfatal:\s+remaining connection slots are reserved\b",
                r"(?i)\bconnection to server at .* port 5432 failed\b",
            ],
            investigation_hint=(
                "Verify database instance health, connection pool limits, active locks/long-running "
                "queries, and network ACLs between the application and database."
            ),
        ),
        ClassificationRuleConfig(
            id="timeout_error",
            name="Timeout Errors",
            priority=20,
            patterns=[
                r"(?i)\b(?:TimeoutError|ReadTimeout|ConnectTimeout|GatewayTimeout|SocketTimeoutException|DeadlineExceeded)\b",
                r"(?i)\b(?:timed out|request timeout|read timeout|connect timeout|upstream timed out|gateway time-out|operation timed out|execution expired)\b",
                r"(?i)\bETIMEDOUT\b",
            ],
            investigation_hint=(
                "Check upstream service latency, timeout settings vs SLA budgets, thread/worker "
                "saturation, and slow external API calls."
            ),
        ),
        ClassificationRuleConfig(
            id="auth_error",
            name="Authentication & Authorization Failures",
            priority=30,
            patterns=[
                r"(?i)\b(?:authentication failed|invalid credentials|unauthorized|forbidden|access denied|permission denied for user|invalid token|jwt expired|token expired|signature verification failed)\b",
                r"(?i)\b(?:AuthError|AuthenticationError|AuthorizationError|InvalidTokenError|TokenExpiredError)\b",
                r"(?i)\bHTTP\s+(?:401|403)\b|\bstatus(?:_code)?\s*[=:]\s*(?:401|403)\b",
            ],
            investigation_hint=(
                "Inspect identity provider status, rotated API keys/certificates, clock skew "
                "affecting JWT expiration, or brute-force login attempts."
            ),
        ),
        ClassificationRuleConfig(
            id="network_error",
            name="Network & Connection Failures",
            priority=40,
            patterns=[
                r"(?i)\b(?:ConnectionRefusedError|ConnectionResetError|ConnectionAbortedError|BrokenPipeError|gaierror|SSLError|CertificateError)\b",
                r"(?i)\b(?:connection refused|connection reset by peer|broken pipe|name or service not known|temporary failure in name resolution|no route to host|network is unreachable|ssl handshake failed|tlsv1 alert)\b",
                r"(?i)\b(?:ECONNREFUSED|ECONNRESET|EHOSTUNREACH|ENETUNREACH|EPIPE)\b",
            ],
            investigation_hint=(
                "Check DNS resolution, target service availability, firewall/security group rules, "
                "TLS certificate validity, and load balancer health."
            ),
        ),
        ClassificationRuleConfig(
            id="filesystem_error",
            name="File System & Permission Errors",
            priority=50,
            patterns=[
                r"(?i)\b(?:FileNotFoundError|PermissionError|FileExistsError|IsADirectoryError|NotADirectoryError|DiskFullError|IOError)\b",
                r"(?i)\b(?:no such file or directory|permission denied|read-only file system|no space left on device|disk quota exceeded|too many open files)\b",
                r"(?i)\b(?:ENOENT|EACCES|EPERM|ENOSPC|EMFILE|ENFILE|EROFS)\b",
            ],
            investigation_hint=(
                "Check disk usage (df -h / inode utilization), file ownership and chmod permissions, "
                "open file descriptor limits (ulimit -n), and mount status."
            ),
        ),
        ClassificationRuleConfig(
            id="resource_exhaustion",
            name="Resource Exhaustion",
            priority=60,
            patterns=[
                r"(?i)\b(?:MemoryError|OutOfMemoryError|OOMKilled|ResourceExhaustedError|QueueFull)\b",
                r"(?i)\b(?:out of memory|cannot allocate memory|memory limit exceeded|cpu throttling|thread pool exhausted|worker pool full|rate limit exceeded|too many requests)\b",
                r"(?i)\bENOMEM\b",
            ],
            investigation_hint=(
                "Inspect container/host memory limits, heap allocations for leaks, worker queue "
                "backlog, and rate-limiting thresholds."
            ),
        ),
        ClassificationRuleConfig(
            id="api_http_error",
            name="API / HTTP Failures",
            priority=70,
            patterns=[
                r"(?i)\b(?:HTTPError|BadGateway|ServiceUnavailable|ClientResponseError|RequestException)\b",
                r'(?i)\b(?:HTTP/\d\.\d["\s]+5\d\d|HTTP\s+5\d\d|status(?:_code)?\s*[=:]\s*5\d\d|500 Internal Server Error|502 Bad Gateway|503 Service Unavailable|504 Gateway Timeout|429 Too Many Requests)\b',
                r"(?i)\b(?:upstream prematurely closed connection|invalid response from upstream|webhook delivery failed)\b",
            ],
            investigation_hint=(
                "Review upstream API status pages, HTTP 5xx/429 response bodies, retry/backoff "
                "policies, and reverse proxy error logs."
            ),
        ),
        ClassificationRuleConfig(
            id="configuration_error",
            name="Configuration Errors",
            priority=80,
            patterns=[
                r"(?i)\b(?:ConfigurationError|ConfigError|ImproperlyConfigured|MissingEnvironmentVariable|ValidationError)\b",
                r"(?i)\b(?:missing required environment variable|invalid configuration|unrecognized setting|failed to load config|schema validation failed|malformed configuration)\b",
            ],
            investigation_hint=(
                "Validate environment variables, deployment secrets/ConfigMaps, and TOML/YAML/JSON "
                "syntax against the application configuration schema."
            ),
        ),
        ClassificationRuleConfig(
            id="application_exception",
            name="Application Exceptions",
            priority=90,
            patterns=[
                r"(?i)\b(?:Traceback \(most recent call last\)|KeyError|ValueError|TypeError|AttributeError|IndexError|ZeroDivisionError|AssertionError|RuntimeError|NameError|ImportError|ModuleNotFoundError|NullPointerException|UnhandledPromiseRejection)\b",
                r"(?i)\b(?:unhandled exception|uncaught exception|segmentation fault|panic:)\b",
            ],
            investigation_hint=(
                "Examine the stack trace filename and line number, inspect recent code deployments, "
                "and add input validation or defensive guards around the failing call."
            ),
        ),
    ]


def create_default_config() -> AnalyzerConfig:
    """Create a complete AnalyzerConfig populated with default rules."""
    return AnalyzerConfig(
        security=SecurityConfig(
            enable_redaction=True,
            csv_formula_protection=True,
            redaction_rules=default_redaction_rules(),
        ),
        fingerprinting=FingerprintingConfig(
            custom_masks=[
                CustomMaskConfig(
                    name="session_token",
                    pattern=r"\bsess_[a-zA-Z0-9]{8,}\b",
                    placeholder="<SESSION_ID>",
                )
            ]
        ),
        anomaly_detection=AnomalyConfig(),
        classification_rules=default_classification_rules(),
    )


def _validate_regex(pattern: str, context: str, errors: list[str]) -> None:
    try:
        re.compile(pattern)
    except re.error as exc:
        errors.append(f"Invalid regular expression in {context}: '{pattern}' ({exc})")


def parse_and_validate_config_dict(raw: dict[str, Any]) -> AnalyzerConfig:
    """Validate a parsed TOML dictionary and construct an AnalyzerConfig."""
    errors: list[str] = []
    cfg = create_default_config()

    allowed_sections = {
        "general",
        "custom_parser",
        "filtering",
        "security",
        "fingerprinting",
        "anomaly_detection",
        "classification",
    }
    for key in raw:
        if key not in allowed_sections:
            errors.append(
                f"Unknown top-level configuration section '[{key}]'. "
                f"Allowed sections: {', '.join(sorted(allowed_sections))}"
            )

    # [general]
    general = raw.get("general", {})
    if not isinstance(general, dict):
        errors.append("Section [general] must be a table.")
    else:
        if "encoding" in general:
            if not isinstance(general["encoding"], str) or not general["encoding"].strip():
                errors.append("general.encoding must be a non-empty string.")
            else:
                cfg.encoding = general["encoding"].strip()
        if "recursive" in general:
            if not isinstance(general["recursive"], bool):
                errors.append("general.recursive must be a boolean.")
            else:
                cfg.recursive = general["recursive"]
        if "default_format" in general:
            fmt = str(general["default_format"]).lower()
            if fmt not in VALID_FORMATS:
                errors.append(
                    f"general.default_format '{fmt}' is invalid. "
                    f"Must be one of: {', '.join(sorted(VALID_FORMATS))}"
                )
            else:
                cfg.default_format = fmt
        if "deduplicate_rotated" in general:
            if not isinstance(general["deduplicate_rotated"], bool):
                errors.append("general.deduplicate_rotated must be a boolean.")
            else:
                cfg.deduplicate_rotated = general["deduplicate_rotated"]
        if "top_n" in general:
            if not isinstance(general["top_n"], int) or general["top_n"] < 1:
                errors.append("general.top_n must be a positive integer.")
            else:
                cfg.top_n = general["top_n"]
        if "failure_severity_threshold" in general:
            sev = str(general["failure_severity_threshold"]).upper()
            if sev not in VALID_SEVERITIES:
                errors.append(
                    f"general.failure_severity_threshold '{sev}' is invalid. "
                    f"Must be one of: {', '.join(sorted(VALID_SEVERITIES))}"
                )
            else:
                cfg.failure_severity_threshold = sev

    # [custom_parser]
    custom_parser = raw.get("custom_parser", {})
    if not isinstance(custom_parser, dict):
        errors.append("Section [custom_parser] must be a table.")
    else:
        if "enabled" in custom_parser:
            if not isinstance(custom_parser["enabled"], bool):
                errors.append("custom_parser.enabled must be a boolean.")
            else:
                cfg.custom_parser_enabled = custom_parser["enabled"]
        if "pattern" in custom_parser:
            pat = custom_parser["pattern"]
            if not isinstance(pat, str):
                errors.append("custom_parser.pattern must be a string.")
            else:
                cfg.custom_parser_pattern = pat
                if pat:
                    _validate_regex(pat, "custom_parser.pattern", errors)
                    if "(?P<message>" not in pat:
                        errors.append(
                            "custom_parser.pattern must include a named group '(?P<message>...)'."
                        )
        if cfg.custom_parser_enabled and not cfg.custom_parser_pattern:
            errors.append("custom_parser.pattern is required when custom_parser.enabled = true.")

    # [filtering]
    filtering = raw.get("filtering", {})
    if not isinstance(filtering, dict):
        errors.append("Section [filtering] must be a table.")
    else:
        if "exclude_patterns" in filtering:
            excl = filtering["exclude_patterns"]
            if not isinstance(excl, list) or not all(isinstance(x, str) for x in excl):
                errors.append("filtering.exclude_patterns must be a list of regex strings.")
            else:
                for idx, pat in enumerate(excl):
                    _validate_regex(pat, f"filtering.exclude_patterns[{idx}]", errors)
                cfg.exclude_patterns = list(excl)

    # [security]
    security = raw.get("security", {})
    if not isinstance(security, dict):
        errors.append("Section [security] must be a table.")
    else:
        if "enable_redaction" in security:
            if not isinstance(security["enable_redaction"], bool):
                errors.append("security.enable_redaction must be a boolean.")
            else:
                cfg.security.enable_redaction = security["enable_redaction"]
        if "csv_formula_protection" in security:
            if not isinstance(security["csv_formula_protection"], bool):
                errors.append("security.csv_formula_protection must be a boolean.")
            else:
                cfg.security.csv_formula_protection = security["csv_formula_protection"]
        if "redaction_rules" in security:
            rules_raw = security["redaction_rules"]
            if not isinstance(rules_raw, list):
                errors.append("security.redaction_rules must be an array of tables.")
            else:
                parsed_redactions: list[RedactionRuleConfig] = []
                for idx, item in enumerate(rules_raw):
                    if not isinstance(item, dict):
                        errors.append(f"security.redaction_rules[{idx}] must be a table.")
                        continue
                    r_name = item.get("name", f"rule_{idx}")
                    r_pat = item.get("pattern", "")
                    r_rep = item.get("replacement", "[REDACTED]")
                    if not isinstance(r_pat, str) or not r_pat:
                        errors.append(
                            f"security.redaction_rules[{idx}] ('{r_name}') requires a non-empty 'pattern'."
                        )
                    else:
                        _validate_regex(r_pat, f"security.redaction_rules[{idx}]", errors)
                    parsed_redactions.append(
                        RedactionRuleConfig(
                            name=str(r_name),
                            pattern=str(r_pat),
                            replacement=str(r_rep),
                        )
                    )
                cfg.security.redaction_rules = parsed_redactions

    # [fingerprinting]
    fp = raw.get("fingerprinting", {})
    if not isinstance(fp, dict):
        errors.append("Section [fingerprinting] must be a table.")
    else:
        for bool_field in (
            "mask_uuids",
            "mask_request_ids",
            "mask_timestamps",
            "mask_ip_addresses",
            "mask_hex_addresses",
            "mask_numbers",
            "mask_durations",
        ):
            if bool_field in fp:
                if not isinstance(fp[bool_field], bool):
                    errors.append(f"fingerprinting.{bool_field} must be a boolean.")
                else:
                    setattr(cfg.fingerprinting, bool_field, fp[bool_field])
        if "custom_masks" in fp:
            masks_raw = fp["custom_masks"]
            if not isinstance(masks_raw, list):
                errors.append("fingerprinting.custom_masks must be an array of tables.")
            else:
                parsed_masks: list[CustomMaskConfig] = []
                for idx, item in enumerate(masks_raw):
                    if not isinstance(item, dict):
                        errors.append(f"fingerprinting.custom_masks[{idx}] must be a table.")
                        continue
                    m_name = item.get("name", f"mask_{idx}")
                    m_pat = item.get("pattern", "")
                    m_ph = item.get("placeholder", "<MASKED>")
                    if not isinstance(m_pat, str) or not m_pat:
                        errors.append(
                            f"fingerprinting.custom_masks[{idx}] ('{m_name}') requires a non-empty 'pattern'."
                        )
                    else:
                        _validate_regex(m_pat, f"fingerprinting.custom_masks[{idx}]", errors)
                    parsed_masks.append(
                        CustomMaskConfig(
                            name=str(m_name),
                            pattern=str(m_pat),
                            placeholder=str(m_ph),
                        )
                    )
                cfg.fingerprinting.custom_masks = parsed_masks

    # [anomaly_detection]
    anom = raw.get("anomaly_detection", {})
    if not isinstance(anom, dict):
        errors.append("Section [anomaly_detection] must be a table.")
    else:
        if "time_window" in anom:
            tw = str(anom["time_window"])
            if tw not in VALID_TIME_WINDOWS:
                errors.append(
                    f"anomaly_detection.time_window '{tw}' is invalid. "
                    f"Must be one of: {', '.join(sorted(VALID_TIME_WINDOWS))}"
                )
            else:
                cfg.anomaly_detection.time_window = tw
        for int_field in (
            "rolling_window_buckets",
            "min_history_buckets",
            "min_spike_count",
            "absolute_threshold",
        ):
            if int_field in anom:
                val = anom[int_field]
                if not isinstance(val, int) or isinstance(val, bool) or val < 1:
                    errors.append(f"anomaly_detection.{int_field} must be a positive integer.")
                else:
                    setattr(cfg.anomaly_detection, int_field, val)
        for float_field in ("ratio_threshold", "mad_z_threshold"):
            if float_field in anom:
                val = anom[float_field]
                if not isinstance(val, (int, float)) or isinstance(val, bool) or float(val) <= 0:
                    errors.append(f"anomaly_detection.{float_field} must be a positive number.")
                else:
                    setattr(cfg.anomaly_detection, float_field, float(val))

    # [classification]
    classification = raw.get("classification", {})
    if not isinstance(classification, dict):
        errors.append("Section [classification] must be a table.")
    else:
        if "rules" in classification:
            rules_list = classification["rules"]
            if not isinstance(rules_list, list) or len(rules_list) == 0:
                errors.append("classification.rules must be a non-empty array of rule tables.")
            else:
                parsed_rules: list[ClassificationRuleConfig] = []
                for idx, r_item in enumerate(rules_list):
                    if not isinstance(r_item, dict):
                        errors.append(f"classification.rules[{idx}] must be a table.")
                        continue
                    r_id = r_item.get("id", "")
                    r_name = r_item.get("name", "")
                    r_prio = r_item.get("priority", 100)
                    r_pats = r_item.get("patterns", [])
                    r_hint = r_item.get("investigation_hint", "")
                    r_sev = r_item.get("severity_override", "")

                    rule_errors_before = len(errors)

                    if not isinstance(r_id, str) or not r_id.strip():
                        errors.append(
                            f"classification.rules[{idx}] requires a non-empty string 'id'."
                        )
                    if not isinstance(r_name, str) or not r_name.strip():
                        errors.append(
                            f"classification.rules[{idx}] requires a non-empty string 'name'."
                        )
                    if not isinstance(r_prio, int) or isinstance(r_prio, bool):
                        errors.append(
                            f"classification.rules[{idx}] ('{r_id}') 'priority' must be an integer."
                        )
                    if (
                        not isinstance(r_pats, list)
                        or len(r_pats) == 0
                        or not all(isinstance(p, str) and p for p in r_pats)
                    ):
                        errors.append(
                            f"classification.rules[{idx}] ('{r_id}') 'patterns' must be a non-empty list of regex strings."
                        )
                    else:
                        for p_idx, pat in enumerate(r_pats):
                            _validate_regex(
                                pat, f"classification.rules[{idx}].patterns[{p_idx}]", errors
                            )
                    if r_sev and str(r_sev).upper() not in VALID_SEVERITIES:
                        errors.append(
                            f"classification.rules[{idx}] ('{r_id}') severity_override '{r_sev}' is invalid."
                        )

                    if len(errors) == rule_errors_before:
                        parsed_rules.append(
                            ClassificationRuleConfig(
                                id=str(r_id).strip(),
                                name=str(r_name).strip(),
                                priority=r_prio if isinstance(r_prio, int) else 100,
                                patterns=[str(p) for p in r_pats],
                                investigation_hint=str(r_hint),
                                severity_override=str(r_sev).upper() if r_sev else "",
                            )
                        )
                if not errors:
                    cfg.classification_rules = sorted(parsed_rules, key=lambda r: r.priority)

    if errors:
        raise ConfigValidationError(errors)

    return cfg


def load_config(config_path: str | Path | None = None) -> AnalyzerConfig:
    """Load and validate a TOML configuration file, or return default config if None."""
    if config_path is None:
        return create_default_config()

    path = Path(config_path)
    if not path.exists():
        raise ConfigValidationError([f"Configuration file does not exist: {path}"])
    if not path.is_file():
        raise ConfigValidationError([f"Configuration path is not a regular file: {path}"])

    try:
        raw_bytes = path.read_bytes()
        raw_dict = tomllib.loads(raw_bytes.decode("utf-8"))
    except UnicodeDecodeError as exc:
        raise ConfigValidationError([f"Configuration file is not valid UTF-8: {exc}"]) from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigValidationError([f"Invalid TOML syntax in {path}: {exc}"]) from exc
    except OSError as exc:
        raise ConfigValidationError([f"Unable to read configuration file {path}: {exc}"]) from exc

    return parse_and_validate_config_dict(raw_dict)
