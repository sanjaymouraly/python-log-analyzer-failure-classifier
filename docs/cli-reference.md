# CLI Reference (`log-analyzer`)

## Subcommands

### 1. `log-analyzer demo`

Generates deterministic synthetic multi-format logs in `samples/logs` and outputs full CSV, JSON, HTML, and PNG reports in `reports/demo`.

```bash
log-analyzer demo [--sample-dir samples/logs] [--output reports/demo] [--seed 42] [--config config.example.toml]
```

### 2. `log-analyzer analyze`

Analyzes one or more files, directories, or glob patterns.

```bash
log-analyzer analyze --input <path1> [<path2> ...] [options]
```

| Option | Description |
| :--- | :--- |
| `--input`, `-i` | One or more log files, directories, or glob patterns (required). |
| `--output`, `-o` | Output directory for reports (`report.html`, `report.json`, `*.csv`, `charts/*.png`). |
| `--config`, `-c` | Path to TOML configuration file. |
| `--format` | Format override: `auto`, `python`, `iso`, `jsonl`, `syslog`, `apache`, `nginx`, `custom`. |
| `--report-formats` | Comma-separated list of exports when `--output` is set: `all`, `json`, `csv`, `html`, `png`. |
| `--severity` | Minimum severity filter (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`). |
| `--exact-severity` | Filter to one exact severity level. |
| `--service` | Filter events by service/application name substring. |
| `--category` | Filter events by failure category ID or name substring. |
| `--search`, `--grep` | Filter events by message/traceback keyword or regular expression. |
| `--exclude` | Regex pattern to exclude noisy messages (repeatable). |
| `--file-filter` | Regex filter applied to discovered log filenames. |
| `--since`, `--start-time` | Include events at or after this ISO-8601 timestamp. |
| `--until`, `--end-time` | Include events at or before this ISO-8601 timestamp. |
| `--window` | Time bucket size for anomaly detection: `1min`, `5min`, `15min`, `1h`, `1d`. |
| `--threshold` | Override confirmed error count threshold per time window. |
| `--ratio-threshold` | Override statistical ratio threshold over baseline. |
| `--mad-z-threshold` | Override robust Median/MAD modified Z-score threshold. |
| `--top-n` | Maximum recurring error groups to display (default: `15`). |
| `--sort` | Group sort order: `count`, `last_seen`, `first_seen`, `severity`. |
| `--encoding` | File text encoding (default: `utf-8`). |
| `--no-recursive` | Disable recursive directory traversal. |
| `--no-dedup` | Disable rotated log overlap deduplication. |
| `--no-redact` | Disable automatic secret/PII redaction. |
| `--incremental` | Skip unchanged files already recorded in the local SQLite state DB. |
| `--state-db` | Path to SQLite state database (default: `.log_analyzer_state.db` when `--incremental` is used). |
| `--fail-on-alert` | Exit with code `2` if any anomaly spike alert is triggered (designed for CI/CD pipelines). |
| `--quiet`, `-q` | Suppress informational progress logs. |
| `--verbose`, `-v` | Enable debug-level diagnostic logging. |

### 3. `log-analyzer validate-config`

Validates TOML syntax, schema types, and regular expressions in a configuration file.

```bash
log-analyzer validate-config --config config.example.toml
```

### 4. `log-analyzer generate-demo`

Generates deterministic synthetic log files without running analysis.

```bash
log-analyzer generate-demo --output samples/logs --seed 42 [--no-spikes]
```

## Exit Codes

| Exit Code | Meaning |
| ---: | :--- |
| `0` | Success (and zero anomaly alerts when `--fail-on-alert` is active). |
| `1` | Configuration error, missing/unreadable input files, or runtime failure. |
| `2` | Anomaly spike alert(s) triggered while `--fail-on-alert` is enabled (or CLI syntax error). |
