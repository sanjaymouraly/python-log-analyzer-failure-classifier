# Configuration Reference

`log-analyzer` works out of the box with sensible defaults and can be customized via a TOML configuration file (`--config config.example.toml`).

Validate any configuration file before running analysis:

```bash
log-analyzer validate-config --config config.example.toml
```

## Configuration Sections

### 1. `[general]`

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `encoding` | `string` | `"utf-8"` | Default text encoding for log files (gracefully falls back on corrupted byte sequences). |
| `recursive` | `bool` | `true` | Recursively scan subdirectories when an input directory is provided. |
| `default_format` | `string` | `"auto"` | Parser mode: `"auto"`, `"python"`, `"iso"`, `"jsonl"`, `"syslog"`, `"apache"`, `"nginx"`, `"custom"`. |
| `deduplicate_rotated` | `bool` | `true` | Skip duplicate events repeated across rotated log file boundaries. |
| `top_n` | `int` | `15` | Maximum number of recurring failure groups to include in summary reports. |
| `failure_severity_threshold` | `string` | `"ERROR"` | Minimum severity treated as a failure (`"WARNING"`, `"ERROR"`, `"CRITICAL"`). |

### 2. `[custom_parser]`

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `enabled` | `bool` | `false` | Enable custom user-defined regular expression parsing. |
| `pattern` | `string` | `""` | Regex containing at least `(?P<message>...)` and optional `timestamp`, `severity`, `service`, `logger`, `error_code`, `request_id`, `source_file`, `source_line`, `exception_type`. |

### 3. `[filtering]`

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `exclude_patterns` | `list[str]` | `[]` | List of regular expressions for noisy log records to ignore during ingestion. |

### 4. `[security]` and `[[security.redaction_rules]]`

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `enable_redaction` | `bool` | `true` | Scrub sensitive secrets, passwords, tokens, and emails before storing or exporting events. |
| `csv_formula_protection` | `bool` | `true` | Prefix CSV cells starting with `=`, `+`, `-`, `@`, `\t`, `\r` with `'` to prevent spreadsheet formula injection. |
| `redaction_rules` | `array` | 7 built-in rules | Each entry specifies `name`, `pattern` (regex), and `replacement`. |

### 5. `[fingerprinting]` and `[[fingerprinting.custom_masks]]`

Controls variable masking when generating error templates (`mask_uuids`, `mask_request_ids`, `mask_timestamps`, `mask_ip_addresses`, `mask_hex_addresses`, `mask_durations`, `mask_numbers`) plus custom `[[fingerprinting.custom_masks]]` tables (`name`, `pattern`, `placeholder`).

### 6. `[anomaly_detection]`

| Key | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `time_window` | `string` | `"5min"` | Aggregation bucket size: `"1min"`, `"5min"`, `"15min"`, `"1h"`, `"1d"`. |
| `rolling_window_buckets` | `int` | `6` | Number of prior buckets used for rolling mean/median baseline calculation. |
| `min_history_buckets` | `int` | `6` | Minimum total time buckets required before statistical anomaly alerts can fire. |
| `min_spike_count` | `int` | `8` | Minimum absolute error count in a bucket required before any alert can fire. |
| `absolute_threshold` | `int` | `25` | Static error ceiling per bucket that triggers a `confirmed_threshold` violation. |
| `ratio_threshold` | `float` | `3.0` | Minimum ratio (`observed / baseline`) required for a `statistical_anomaly`. |
| `mad_z_threshold` | `float` | `3.5` | Minimum robust Median/MAD modified Z-score required for a `statistical_anomaly`. |

### 7. `[[classification.rules]]`

Each classification rule defines:
- `id`: Machine identifier (e.g., `"database_error"`).
- `name`: Human-readable category name (e.g., `"Database Errors"`).
- `priority`: Integer evaluation order (lowest integer evaluated first).
- `patterns`: Non-empty list of regular expressions matched against event message, exception type, error code, and traceback tail.
- `investigation_hint`: Actionable engineering guidance displayed in reports.
- `severity_override`: Optional severity level override when the rule matches.
