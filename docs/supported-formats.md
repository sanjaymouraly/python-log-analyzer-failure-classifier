# Supported Log Formats & Multiline Handling

`log-analyzer` automatically detects common application and infrastructure log formats per file and per line (`--format auto`) or accepts an explicit format flag (`--format <name>`).

## 1. Standard Python Logging (`--format python`)

Supports standard `logging.Formatter` patterns as well as `logging.basicConfig` lines without timestamps:

```text
2026-10-16 08:50:05,000 - catalog.db - CRITICAL - [req-1135] (db_pool.py:118) Database connection failed
2026-10-16 10:15:30,999 WARNING [orders] checkout:88 - Slow inventory query
ERROR:catalog.LegacySync:Legacy sync task encountered an uncategorized checksum mismatch on shard 4
```

## 2. ISO-8601 Application Logs (`--format iso`)

Supports UTC (`Z`) and timezone-offset (`+05:30`, `-04:00`) ISO-8601 timestamps with bracketed or key-value service/component metadata:

```text
2026-10-16T09:25:08Z [ERROR] [payment-service] [payment.gateway] (gateway.py:219) [req-1228] ReadTimeout: ETIMEDOUT Upstream payment processor timed out after 5000ms
2026-10-16 12:00:00+05:30 WARN service=inventory component=syncLag High replication lag detected
```

## 3. JSON Lines / Structured Logs (`--format jsonl`)

Parses newline-delimited JSON objects and maps standard observability keys (`timestamp`/`time`/`ts`/`@timestamp`, `level`/`severity`, `service`/`app`, `logger`/`module`, `message`/`msg`, `exception`/`exception_type`, `error_code`/`code`/`status_code`, `file`/`filename`, `line`/`lineno`, `request_id`/`corr_id`/`trace_id`, `traceback`/`stack_trace`):

```json
{"timestamp": "2026-10-16T08:01:15Z", "level": "ERROR", "service": "auth-service", "logger": "auth.jwt", "request_id": "req-1013", "exception": "AuthenticationError", "error_code": "HTTP_401", "file": "jwt_verifier.py", "line": 128, "message": "Authentication failed: JWT signature verification failed"}
```

## 4. Syslog RFC 3164 & RFC 5424 (`--format syslog`)

Extracts RFC priority (`<PRI>`), timestamp, hostname, service/tag, PID, and message severity:

```text
<35>Oct 16 08:03:15 prod-worker-01 report-exporter[2400]: [ERROR] [req-1014] (exporter.py:91) PermissionError: [Errno 13] EACCES: Permission denied writing '/var/spool/exports/batch_0.csv'
<34>1 2026-10-16T08:28:50Z prod-worker-02 ml-scorer 3190 OOM99 - [CRITICAL] [req-1081] (scorer.py:310) MemoryError: ENOMEM Out of memory allocating tensor buffer of 2048MB
```

## 5. Apache & Nginx Error Logs (`--format apache` / `--format nginx`)

```text
[Fri Oct 16 10:15:30.123456 2026] [core:error] [pid 1234:tid 5678] [client 10.0.0.12:54321] AH00124: Request exceeded the limit of 10 internal redirects
2026/10/16 08:18:30 [error] 1842#1842: *8803 connect() failed (111: ECONNREFUSED: Connection refused) while connecting to upstream, client: 10.0.12.3, server: api.internal
```

## 6. Custom User-Defined Regex (`--format custom`)

Configure `[custom_parser]` in your TOML configuration file with named capture groups (`(?P<timestamp>...)`, `(?P<severity>...)`, `(?P<service>...)`, `(?P<message>...)`, etc.).

## 7. Multiline Traceback Assembly

Multiline Python tracebacks (including chained exceptions with `During handling of the above exception...` or `The above exception was the direct cause...`), Java/Node stack frames (`at ...`, `Caused by:`), and indented continuations are automatically attached to their parent log header event as a single logical `LogEvent`. The innermost source file, line number, and final exception type are automatically extracted.
