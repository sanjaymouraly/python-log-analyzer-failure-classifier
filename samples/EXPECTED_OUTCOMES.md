# Ground-Truth Expected Outcomes for `samples/logs` (`seed=42`)

The bundled demonstration dataset in `samples/logs` is generated deterministically (`log-analyzer generate-demo --output samples/logs --seed 42` or `log-analyzer demo`). You can independently verify the analyzer's accuracy against these exact ground-truth counts.

## 1. Dataset Overview & Files

Timeline: **2026-10-16T08:00:00Z** to **2026-10-16T10:00:00Z** (24 continuous 5-minute buckets).

| File Name | Format | Description |
| :--- | :--- | :--- |
| `app_server.log.2.gz` | Python Standard Logging (`.gz`) | Rotated archive (`08:00Z` – `08:40Z`), includes multiline `KeyError` tracebacks |
| `app_server.log.1` | Python Standard Logging | Rotated log (`08:40Z` – `09:20Z`), includes the `08:50Z` Database Error spike |
| `app_server.log` | Python Standard Logging | Active log (`09:20Z` – `10:00Z`), includes 2 rotated overlap lines, 1 malformed line, and 1 missing-timestamp `basicConfig` line |
| `auth_service.jsonl` | Structured JSON Lines (`.jsonl`) | OAuth/JWT records (`+05:30` and `Z`), includes `AuthenticationError` events and 1 broken JSON line |
| `payment_iso.log` | ISO-8601 Application Log | Payment ledger & gateway records (`-04:00` and `Z`), includes the `09:25Z` `ReadTimeout` burst |
| `gateway_nginx_error.log` | Nginx Error Log | Upstream `ECONNREFUSED` connection failures |
| `worker_syslog.log` | Syslog (RFC 3164 & RFC 5424) | Background worker `PermissionError` (`EACCES`) and `MemoryError` (`ENOMEM`) events |

## 2. Expected Ingestion & Severity Counts

| Metric | Expected Value |
| :--- | ---: |
| **Files Scanned** | `7` |
| **Total Raw Lines Read** | `620` |
| **Total Logical Events Parsed** | `412` |
| **Rotated Duplicate Overlaps Skipped** | `2` |
| **Total Unique Events Analyzed** | `410` |
| **Malformed / Corrupted Lines Reported** | `2` |
| **Events with Missing Timestamps** | `1` |
| **Sensitive Values Redacted** | `130` |
| **`CRITICAL` Events** | `34` (8.3%) |
| **`ERROR` Events** | `76` (18.5%) |
| **`WARNING` Events** | `12` (2.9%) |
| **`INFO` Events** | `240` (58.5%) |
| **`DEBUG` Events** | `48` (11.7%) |
| **Total Failure Events (`ERROR` + `CRITICAL`)** | `110` |

## 3. Expected Failure Classifications & Error Fingerprints (`10` Groups)

| Rank | Category Name | Category ID | Expected Count | Fingerprint | Exception / Code |
| ---: | :--- | :--- | ---: | :--- | :--- |
| 1 | **Database Errors** | `database_error` | `32` | `ea2d88293e42` | `psycopg2.OperationalError` / `08006` |
| 2 | **Authentication & Authorization Failures** | `auth_error` | `24` | `174f1f55b73c` | `AuthenticationError` / `HTTP_401` |
| 3 | **Timeout Errors** | `timeout_error` | `18` | `5bcf31e1c77d` | `ReadTimeout` / `ETIMEDOUT` |
| 4 | **File System & Permission Errors** | `filesystem_error` | `12` | `707745a53ed2` | `PermissionError` / `EACCES` |
| 5 | **Application Exceptions** | `application_exception` | `12` | `6bddc3762c70` | `KeyError` |
| 6 | **Network & Connection Failures** | `network_error` | `4` | `b9fd22edc231` | `ECONNREFUSED` |
| 7 | **API / HTTP Failures** | `api_http_error` | `3` | `a954dec9cbf3` | `HTTPError` / `HTTP_502` |
| 8 | **Resource Exhaustion** | `resource_exhaustion` | `2` | `14ff5fd39845` | `MemoryError` / `ENOMEM` |
| 9 | **Configuration Errors** | `configuration_error` | `2` | `f89f257dde8b` | `ConfigurationError` |
| 10 | **Uncategorized Errors** | `uncategorized_error` | `1` | `9539ba4d890a` | None (Missing timestamp record) |
| **Total** | | | **`110`** | **`10` groups** | |

## 4. Expected Anomaly Spike Alerts (`2` Alerts)

1. **`ALERT-001` (`2026-10-16T08:50:00Z` – `08:55:00Z`)**:
   - **Alert Type**: `combined` (Confirmed Threshold Violation + Statistical Anomaly Indicator)
   - **Severity**: `CRITICAL`
   - **Observed Errors**: `34` (Threshold: `25`)
   - **Rolling Baseline Median**: `3.0` (`11.3x` baseline, Modified Z-score `20.91`)
   - **Primary Driver**: `Database Errors` in service `catalog`
2. **`ALERT-002` (`2026-10-16T09:25:00Z` – `09:30:00Z`)**:
   - **Alert Type**: `statistical_anomaly` (Statistical Anomaly Indicator — below static threshold of `25`, caught via rolling baseline & Median/MAD outlier detection)
   - **Severity**: `HIGH`
   - **Observed Errors**: `20` (Threshold: `25`)
   - **Rolling Baseline Median**: `2.5` (`6.7x` baseline, Modified Z-score `11.47`)
   - **Primary Driver**: `Timeout Errors` in service `payment-service`
