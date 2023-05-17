"""End-to-end CLI tests covering commands, filtering, exit codes, and ground-truth demo verification."""

from __future__ import annotations

import json
from pathlib import Path

from log_analyzer.cli import EXIT_ALERT_TRIGGERED, EXIT_ERROR, EXIT_OK, main
from log_analyzer.demo_generator import generate_demo_dataset


def test_cli_validate_config_and_help(tmp_path: Path) -> None:
    assert main([]) == EXIT_OK
    assert main(["validate-config", "--config", "config.example.toml"]) == EXIT_OK

    bad_cfg = tmp_path / "bad.toml"
    bad_cfg.write_text("[general]\ndefault_format = 'not_a_format'\n", encoding="utf-8")
    assert main(["validate-config", "--config", str(bad_cfg)]) == EXIT_ERROR


def test_cli_demo_ground_truth_verification(tmp_path: Path) -> None:
    sample_dir = tmp_path / "samples_with_spaces" / "demo logs"
    out_dir = tmp_path / "reports_with_spaces" / "demo out"

    manifest = generate_demo_dataset(sample_dir, seed=42, include_spikes=True)
    rc = main(
        [
            "demo",
            "--sample-dir",
            str(sample_dir),
            "--output",
            str(out_dir),
            "--seed",
            "42",
            "--quiet",
        ]
    )
    assert rc == EXIT_OK

    report_json = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
    summary = report_json["summary"]

    assert summary["total_files_scanned"] == 7
    assert summary["total_events_analyzed"] == manifest.expected_total_events == 410
    assert summary["total_error_events"] == manifest.expected_error_events == 110
    assert summary["total_warning_events"] == manifest.expected_warning_events == 12
    assert summary["malformed_lines_count"] == manifest.expected_malformed_lines == 2
    assert summary["missing_timestamp_count"] == manifest.expected_missing_timestamp_events == 1
    assert summary["duplicate_events_skipped"] == manifest.expected_duplicate_overlaps == 2
    assert summary["unique_error_groups"] == 10
    assert summary["anomaly_alerts_triggered"] == 2

    # Check exact category counts match manifest ground truth
    for cat_name, expected_cnt in manifest.expected_category_counts.items():
        assert report_json["category_counts"][cat_name] == expected_cnt


def test_cli_analyze_filtering_and_fail_on_alert(tmp_path: Path) -> None:
    sample_dir = tmp_path / "logs"
    out_dir = tmp_path / "out"
    generate_demo_dataset(sample_dir, seed=42, include_spikes=True)

    # 1. --fail-on-alert returns EXIT_ALERT_TRIGGERED (2) when spikes exist
    rc_alert = main(
        [
            "analyze",
            "--input",
            str(sample_dir),
            "--fail-on-alert",
            "--quiet",
        ]
    )
    assert rc_alert == EXIT_ALERT_TRIGGERED

    # 2. Filtering by severity, service, category, time window, and search
    rc_filtered = main(
        [
            "analyze",
            "--input",
            str(sample_dir),
            "--output",
            str(out_dir),
            "--severity",
            "ERROR",
            "--service",
            "catalog",
            "--category",
            "database_error",
            "--since",
            "2026-10-16T08:45:00Z",
            "--until",
            "2026-10-16T09:00:00Z",
            "--search",
            "SQLSTATE",
            "--sort",
            "last_seen",
            "--top-n",
            "5",
            "--report-formats",
            "json",
            "--quiet",
        ]
    )
    assert rc_filtered == EXIT_OK
    filtered_data = json.loads((out_dir / "report.json").read_text(encoding="utf-8"))
    assert filtered_data["summary"]["total_events_analyzed"] == 32
    assert filtered_data["summary"]["total_error_events"] == 32
    assert len(filtered_data["error_groups"]) == 1
    assert filtered_data["error_groups"][0]["category_id"] == "database_error"

    # 3. Non-existent input path returns EXIT_ERROR (1)
    assert main(["analyze", "--input", str(tmp_path / "does_not_exist")]) == EXIT_ERROR


def test_cli_generate_demo_and_argument_validation_errors(tmp_path: Path) -> None:
    gen_dir = tmp_path / "no_spike_logs"
    rc_gen = main(["generate-demo", "--output", str(gen_dir), "--seed", "7", "--no-spikes"])
    assert rc_gen == EXIT_OK

    # Analyzing baseline logs without spikes with --fail-on-alert returns EXIT_OK (0)
    rc_no_alert = main(
        [
            "analyze",
            "--input",
            str(gen_dir),
            "--fail-on-alert",
            "--sort",
            "severity",
            "--window",
            "15min",
            "--threshold",
            "50",
            "--ratio-threshold",
            "4.0",
            "--mad-z-threshold",
            "4.0",
            "--no-recursive",
            "--no-dedup",
            "--no-redact",
            "--encoding",
            "utf-8",
            "--quiet",
        ]
    )
    assert rc_no_alert == EXIT_OK

    # Test invalid CLI argument values return EXIT_ERROR
    assert main(["analyze", "--input", str(gen_dir), "--threshold", "0"]) == EXIT_ERROR
    assert main(["analyze", "--input", str(gen_dir), "--ratio-threshold", "-1"]) == EXIT_ERROR
    assert main(["analyze", "--input", str(gen_dir), "--mad-z-threshold", "0"]) == EXIT_ERROR
    assert main(["analyze", "--input", str(gen_dir), "--top-n", "0"]) == EXIT_ERROR
    assert main(["analyze", "--input", str(gen_dir), "--since", "bad-date"]) == EXIT_ERROR
    assert main(["analyze", "--input", str(gen_dir), "--until", "bad-date"]) == EXIT_ERROR
    assert (
        main(
            [
                "analyze",
                "--input",
                str(gen_dir),
                "--since",
                "2026-10-16T12:00:00Z",
                "--until",
                "2026-10-16T08:00:00Z",
            ]
        )
        == EXIT_ERROR
    )
    assert main(["analyze", "--input", str(gen_dir), "--search", "[unclosed"]) == EXIT_ERROR
    assert main(["analyze", "--input", str(gen_dir), "--exclude", "[unclosed"]) == EXIT_ERROR
