"""Command-line interface (`log-analyzer`) built with argparse."""

from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from collections.abc import Sequence

from log_analyzer import __version__
from log_analyzer.aggregator import FilterCriteria
from log_analyzer.config import (
    VALID_FORMATS,
    VALID_SEVERITIES,
    VALID_TIME_WINDOWS,
    ConfigValidationError,
    load_config,
)
from log_analyzer.demo_generator import generate_demo_dataset
from log_analyzer.normalizer import parse_and_normalize_timestamp
from log_analyzer.pipeline import run_analysis_pipeline
from log_analyzer.reporter import format_terminal_summary

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_ALERT_TRIGGERED = 2


def _configure_logging(verbose: bool = False, quiet: bool = False) -> None:
    level = logging.WARNING if quiet else (logging.DEBUG if verbose else logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )


def build_parser() -> argparse.ArgumentParser:
    """Construct the top-level ArgumentParser and subcommands."""
    parser = argparse.ArgumentParser(
        prog="log-analyzer",
        description=(
            "Python Log Analyzer & Failure Classifier — Local-first application log "
            "ingestion, failure classification, fingerprinting, and spike detection."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    subparsers = parser.add_subparsers(dest="command", metavar="<command>")

    # -------------------------------------------------------------------------
    # Subcommand: analyze
    # -------------------------------------------------------------------------
    analyze_p = subparsers.add_parser(
        "analyze",
        help="Analyze application log files or directories and generate reports.",
        description="Ingest, parse, classify, group, and detect anomalies in application logs.",
    )
    analyze_p.add_argument(
        "--input",
        "-i",
        nargs="+",
        required=True,
        help="One or more log files, directories, or glob patterns to analyze.",
    )
    analyze_p.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help="Output directory for generated reports (CSV, JSON, HTML, PNG charts).",
    )
    analyze_p.add_argument(
        "--config",
        "-c",
        type=str,
        default=None,
        help="Path to TOML configuration file.",
    )
    analyze_p.add_argument(
        "--format",
        type=str,
        choices=sorted(VALID_FORMATS),
        default=None,
        help="Log parser format override (default: auto).",
    )
    analyze_p.add_argument(
        "--report-formats",
        type=str,
        default="all",
        help="Comma-separated export formats when --output is given: all,json,csv,html,png (default: all).",
    )
    analyze_p.add_argument(
        "--severity",
        type=str,
        choices=sorted(VALID_SEVERITIES),
        default=None,
        help="Filter events to those at or above this severity level (e.g. ERROR, WARNING).",
    )
    analyze_p.add_argument(
        "--exact-severity",
        type=str,
        choices=sorted(VALID_SEVERITIES),
        default=None,
        help="Filter events to only this exact severity level.",
    )
    analyze_p.add_argument(
        "--service",
        type=str,
        default=None,
        help="Filter events by service/application name substring.",
    )
    analyze_p.add_argument(
        "--category",
        type=str,
        default=None,
        help="Filter events by error category ID or name substring.",
    )
    analyze_p.add_argument(
        "--search",
        "--grep",
        dest="search",
        type=str,
        default=None,
        help="Filter events matching this keyword or regular expression.",
    )
    analyze_p.add_argument(
        "--exclude",
        action="append",
        default=[],
        help="Regex pattern to exclude matching noisy log events (can be specified multiple times).",
    )
    analyze_p.add_argument(
        "--file-filter",
        type=str,
        default=None,
        help="Regex pattern to filter discovered filenames.",
    )
    analyze_p.add_argument(
        "--since",
        "--start-time",
        dest="since",
        type=str,
        default=None,
        help="Include events at or after this ISO-8601 timestamp (e.g. 2026-10-16T08:30:00Z).",
    )
    analyze_p.add_argument(
        "--until",
        "--end-time",
        dest="until",
        type=str,
        default=None,
        help="Include events at or before this ISO-8601 timestamp.",
    )
    analyze_p.add_argument(
        "--window",
        type=str,
        choices=sorted(VALID_TIME_WINDOWS),
        default=None,
        help="Anomaly detection time bucket size (1min, 5min, 15min, 1h, 1d).",
    )
    analyze_p.add_argument(
        "--threshold",
        type=int,
        default=None,
        help="Override confirmed error spike count threshold per window.",
    )
    analyze_p.add_argument(
        "--ratio-threshold",
        type=float,
        default=None,
        help="Override statistical spike ratio threshold over baseline.",
    )
    analyze_p.add_argument(
        "--mad-z-threshold",
        type=float,
        default=None,
        help="Override robust Median/MAD modified Z-score threshold.",
    )
    analyze_p.add_argument(
        "--top-n",
        type=int,
        default=None,
        help="Number of top recurring failure groups to include in reports.",
    )
    analyze_p.add_argument(
        "--sort",
        type=str,
        choices=["count", "last_seen", "first_seen", "severity"],
        default="count",
        help="Sort order for recurring failure groups (default: count).",
    )
    analyze_p.add_argument(
        "--encoding",
        type=str,
        default=None,
        help="Character encoding for log files (default: utf-8).",
    )
    analyze_p.add_argument(
        "--no-recursive",
        action="store_true",
        help="Disable recursive directory scanning.",
    )
    analyze_p.add_argument(
        "--no-dedup",
        action="store_true",
        help="Disable automatic deduplication across rotated log files.",
    )
    analyze_p.add_argument(
        "--no-redact",
        action="store_true",
        help="Disable automatic sensitive data redaction in outputs.",
    )
    analyze_p.add_argument(
        "--incremental",
        action="store_true",
        help="Skip unchanged files that were already analyzed in the SQLite state DB.",
    )
    analyze_p.add_argument(
        "--state-db",
        type=str,
        default=None,
        help="Path to SQLite state database for incremental processing and run history.",
    )
    analyze_p.add_argument(
        "--fail-on-alert",
        action="store_true",
        help="Exit with code 2 if one or more anomaly spike alerts are triggered (for CI/CD).",
    )
    analyze_p.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress non-essential terminal progress messages.",
    )
    analyze_p.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose debug logging.",
    )

    # -------------------------------------------------------------------------
    # Subcommand: demo
    # -------------------------------------------------------------------------
    demo_p = subparsers.add_parser(
        "demo",
        help="Generate bundled synthetic logs and run a complete end-to-end demonstration.",
        description=(
            "Create or use safe bundled example logs in samples/logs and produce "
            "complete CSV, JSON, HTML, and PNG reports."
        ),
    )
    demo_p.add_argument(
        "--sample-dir",
        type=str,
        default="samples/logs",
        help="Directory where synthetic demo log files are stored/generated (default: samples/logs).",
    )
    demo_p.add_argument(
        "--output",
        "-o",
        type=str,
        default="reports/demo",
        help="Directory where demo reports and charts are written (default: reports/demo).",
    )
    demo_p.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for deterministic demo dataset generation (default: 42).",
    )
    demo_p.add_argument(
        "--config",
        "-c",
        type=str,
        default=None,
        help="Optional TOML config file path.",
    )
    demo_p.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Minimal console output.",
    )

    # -------------------------------------------------------------------------
    # Subcommand: validate-config
    # -------------------------------------------------------------------------
    val_p = subparsers.add_parser(
        "validate-config",
        help="Validate a TOML configuration file and report any schema or regex errors.",
    )
    val_p.add_argument(
        "--config",
        "-c",
        type=str,
        required=True,
        help="Path to the TOML configuration file to validate.",
    )

    # -------------------------------------------------------------------------
    # Subcommand: generate-demo
    # -------------------------------------------------------------------------
    gen_p = subparsers.add_parser(
        "generate-demo",
        help="Generate synthetic multi-format sample logs without running analysis.",
    )
    gen_p.add_argument(
        "--output",
        "-o",
        type=str,
        default="samples/logs",
        help="Directory to write synthetic log files (default: samples/logs).",
    )
    gen_p.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Deterministic random seed (default: 42).",
    )
    gen_p.add_argument(
        "--no-spikes",
        action="store_true",
        help="Generate baseline logs without anomaly spikes.",
    )

    return parser


def _handle_validate_config(args: argparse.Namespace) -> int:
    try:
        cfg = load_config(args.config)
        print(f"[OK] Configuration file '{args.config}' is valid.")
        print(f"     Default format           : {cfg.default_format}")
        print(f"     Failure severity         : {cfg.failure_severity_threshold}")
        print(f"     Classification rules     : {len(cfg.classification_rules)} rules loaded")
        print(
            f"     Redaction rules          : {len(cfg.security.redaction_rules)} rules (enabled={cfg.security.enable_redaction})"
        )
        print(
            f"     Anomaly window           : {cfg.anomaly_detection.time_window} "
            f"(threshold={cfg.anomaly_detection.absolute_threshold}, ratio={cfg.anomaly_detection.ratio_threshold}x, mad_z={cfg.anomaly_detection.mad_z_threshold})"
        )
        return EXIT_OK
    except ConfigValidationError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return EXIT_ERROR


def _handle_generate_demo(args: argparse.Namespace) -> int:
    try:
        manifest = generate_demo_dataset(
            output_dir=args.output,
            seed=args.seed,
            include_spikes=not args.no_spikes,
        )
        print(
            f"[OK] Generated {len(manifest.files_created)} synthetic log files in '{manifest.output_dir}'."
        )
        print(json.dumps(manifest.to_dict(), indent=2))
        return EXIT_OK
    except Exception as exc:
        print(f"[ERROR] Failed to generate demo dataset: {exc}", file=sys.stderr)
        return EXIT_ERROR


def _handle_demo(args: argparse.Namespace) -> int:
    _configure_logging(verbose=False, quiet=args.quiet)
    try:
        cfg = load_config(args.config)
        manifest = generate_demo_dataset(
            output_dir=args.sample_dir, seed=args.seed, include_spikes=True
        )
        if not args.quiet:
            print(
                f"[INFO] Prepared deterministic demo logs in '{manifest.output_dir}' "
                f"({len(manifest.files_created)} files, seed={manifest.seed})."
            )

        result, report_paths = run_analysis_pipeline(
            input_paths=[manifest.output_dir],
            config=cfg,
            output_dir=args.output,
            export_formats={"all"},
        )
        summary_text = format_terminal_summary(result, report_paths=report_paths)
        print(summary_text)
        return EXIT_OK
    except ConfigValidationError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:
        print(f"[ERROR] Demo execution failed: {exc}", file=sys.stderr)
        return EXIT_ERROR


def _handle_analyze(args: argparse.Namespace) -> int:
    _configure_logging(verbose=args.verbose, quiet=args.quiet)
    try:
        cfg = load_config(args.config)
    except ConfigValidationError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return EXIT_ERROR

    # Apply CLI overrides to config
    if args.encoding:
        cfg.encoding = args.encoding
    if args.no_recursive:
        cfg.recursive = False
    if args.no_dedup:
        cfg.deduplicate_rotated = False
    if args.no_redact:
        cfg.security.enable_redaction = False
    if args.window:
        cfg.anomaly_detection.time_window = args.window
    if args.threshold is not None:
        if args.threshold < 1:
            print("[ERROR] --threshold must be a positive integer.", file=sys.stderr)
            return EXIT_ERROR
        cfg.anomaly_detection.absolute_threshold = args.threshold
    if args.ratio_threshold is not None:
        if args.ratio_threshold <= 0:
            print("[ERROR] --ratio-threshold must be > 0.", file=sys.stderr)
            return EXIT_ERROR
        cfg.anomaly_detection.ratio_threshold = args.ratio_threshold
    if args.mad_z_threshold is not None:
        if args.mad_z_threshold <= 0:
            print("[ERROR] --mad-z-threshold must be > 0.", file=sys.stderr)
            return EXIT_ERROR
        cfg.anomaly_detection.mad_z_threshold = args.mad_z_threshold
    if args.top_n is not None:
        if args.top_n < 1:
            print("[ERROR] --top-n must be a positive integer.", file=sys.stderr)
            return EXIT_ERROR
        cfg.top_n = args.top_n

    # Parse optional --since and --until timestamps
    since_dt = None
    if args.since:
        since_dt, _, _, ok = parse_and_normalize_timestamp(args.since)
        if not ok or since_dt is None:
            print(f"[ERROR] Invalid --since timestamp: '{args.since}'", file=sys.stderr)
            return EXIT_ERROR

    until_dt = None
    if args.until:
        until_dt, _, _, ok = parse_and_normalize_timestamp(args.until)
        if not ok or until_dt is None:
            print(f"[ERROR] Invalid --until timestamp: '{args.until}'", file=sys.stderr)
            return EXIT_ERROR

    if since_dt and until_dt and since_dt > until_dt:
        print("[ERROR] --since timestamp cannot be later than --until timestamp.", file=sys.stderr)
        return EXIT_ERROR

    # Validate --search and --exclude regexes
    if args.search:
        try:
            re.compile(args.search)
        except re.error as exc:
            print(
                f"[ERROR] Invalid --search regular expression '{args.search}': {exc}",
                file=sys.stderr,
            )
            return EXIT_ERROR

    combined_excludes = list(cfg.exclude_patterns) + list(args.exclude or [])
    for ex_pat in combined_excludes:
        try:
            re.compile(ex_pat)
        except re.error as exc:
            print(
                f"[ERROR] Invalid --exclude regular expression '{ex_pat}': {exc}", file=sys.stderr
            )
            return EXIT_ERROR

    criteria = FilterCriteria(
        since=since_dt,
        until=until_dt,
        min_severity=args.severity,
        exact_severity=args.exact_severity,
        service=args.service,
        category=args.category,
        search_pattern=args.search,
        exclude_patterns=combined_excludes,
        sort_by=args.sort,
        top_n=cfg.top_n,
    )

    export_formats = {
        fmt.strip().lower() for fmt in (args.report_formats or "all").split(",") if fmt.strip()
    }

    try:
        result, report_paths = run_analysis_pipeline(
            input_paths=args.input,
            config=cfg,
            criteria=criteria,
            format_override=args.format,
            file_filter=args.file_filter,
            incremental=args.incremental,
            state_db_path=args.state_db,
            output_dir=args.output,
            export_formats=export_formats,
        )
    except FileNotFoundError as exc:
        print(f"[ERROR] {exc}", file=sys.stderr)
        return EXIT_ERROR
    except Exception as exc:
        print(f"[ERROR] Analysis failed: {exc}", file=sys.stderr)
        return EXIT_ERROR

    summary_text = format_terminal_summary(result, report_paths=report_paths)
    print(summary_text)

    if args.fail_on_alert and len(result.anomaly_alerts) > 0:
        print(
            f"\n[ALERT] Exiting with code {EXIT_ALERT_TRIGGERED} because --fail-on-alert is set "
            f"and {len(result.anomaly_alerts)} anomaly alert(s) were triggered.",
            file=sys.stderr,
        )
        return EXIT_ALERT_TRIGGERED

    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    """Main CLI entry point returning an integer exit code."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return EXIT_OK

    if args.command == "validate-config":
        return _handle_validate_config(args)
    if args.command == "generate-demo":
        return _handle_generate_demo(args)
    if args.command == "demo":
        return _handle_demo(args)
    if args.command == "analyze":
        return _handle_analyze(args)

    parser.print_help()
    return EXIT_ERROR


if __name__ == "__main__":
    sys.exit(main())
