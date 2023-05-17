"""Integration tests for the end-to-end analysis pipeline."""

from __future__ import annotations

from pathlib import Path

import pytest

from log_analyzer.config import create_default_config
from log_analyzer.pipeline import run_analysis_pipeline


class TestRunAnalysisPipeline:
    def test_pipeline_with_sample_logs(self, tmp_path: Path):
        log_file = tmp_path / "test.log"
        log_file.write_text(
            "2026-01-01 12:00:00,000 INFO [app] started\n"
            "2026-01-01 12:00:01,000 ERROR [app] Database connection failed\n"
            "2026-01-01 12:00:02,000 ERROR [app] Database connection failed\n"
            "2026-01-01 12:00:03,000 INFO [app] recovered\n",
            encoding="utf-8",
        )

        config = create_default_config()
        result, paths = run_analysis_pipeline(
            input_paths=[str(log_file)],
            config=config,
            output_dir=tmp_path / "reports",
            export_formats={"json"},
        )

        assert result.total_events_parsed == 4
        assert result.total_error_events == 2
        assert len(result.error_groups) >= 1
        assert "json_report" in paths

    def test_pipeline_with_multiple_files(self, tmp_path: Path):
        (tmp_path / "a.log").write_text(
            "2026-01-01 12:00:00,000 ERROR [app] Error A\n",
            encoding="utf-8",
        )
        (tmp_path / "b.log").write_text(
            "2026-01-01 12:00:01,000 ERROR [app] Error B\n",
            encoding="utf-8",
        )

        config = create_default_config()
        result, paths = run_analysis_pipeline(
            input_paths=[str(tmp_path)],
            config=config,
            export_formats={"json"},
        )

        assert result.total_files_scanned == 2
        assert result.total_events_parsed == 2

    def test_pipeline_with_jsonl(self, tmp_path: Path):
        log_file = tmp_path / "test.jsonl"
        log_file.write_text(
            '{"timestamp": "2026-01-01T12:00:00Z", "level": "ERROR", "message": "failed", "service": "api"}\n',
            encoding="utf-8",
        )

        config = create_default_config()
        result, paths = run_analysis_pipeline(
            input_paths=[str(log_file)],
            config=config,
            export_formats={"json"},
        )

        assert result.total_events_parsed == 1
        assert result.total_error_events == 1

    def test_pipeline_with_gzip(self, tmp_path: Path):
        import gzip

        gz_file = tmp_path / "test.log.gz"
        with gzip.open(gz_file, "wt", encoding="utf-8") as f:
            f.write("2026-01-01 12:00:00,000 ERROR [app] gzipped error\n")

        config = create_default_config()
        result, paths = run_analysis_pipeline(
            input_paths=[str(gz_file)],
            config=config,
            export_formats={"json"},
        )

        assert result.total_events_parsed == 1

    def test_pipeline_empty_directory(self, tmp_path: Path):
        config = create_default_config()
        with pytest.raises(FileNotFoundError):
            run_analysis_pipeline(
                input_paths=[str(tmp_path)],
                config=config,
            )

    def test_pipeline_with_filters(self, tmp_path: Path):
        from log_analyzer.aggregator import FilterCriteria

        log_file = tmp_path / "test.log"
        log_file.write_text(
            "2026-01-01 12:00:00,000 ERROR [app] Database error\n"
            "2026-01-01 12:00:01,000 ERROR [app] Auth error\n"
            "2026-01-01 12:00:02,000 INFO [app] normal\n",
            encoding="utf-8",
        )

        config = create_default_config()
        criteria = FilterCriteria(search_pattern="Database")
        result, paths = run_analysis_pipeline(
            input_paths=[str(log_file)],
            config=config,
            criteria=criteria,
            export_formats={"json"},
        )

        assert result.total_events_analyzed == 1

    def test_pipeline_exports_all_formats(self, tmp_path: Path):
        log_file = tmp_path / "test.log"
        log_file.write_text(
            "2026-01-01 12:00:00,000 ERROR [app] error\n",
            encoding="utf-8",
        )

        config = create_default_config()
        result, paths = run_analysis_pipeline(
            input_paths=[str(log_file)],
            config=config,
            output_dir=tmp_path / "reports",
            export_formats={"json", "csv", "html", "png"},
        )

        assert "json_report" in paths
        assert "html_report" in paths
        assert "error_groups_csv" in paths

    def test_pipeline_with_format_override(self, tmp_path: Path):
        log_file = tmp_path / "test.log"
        log_file.write_text(
            "2026-01-01 12:00:00,000 ERROR [app] error\n",
            encoding="utf-8",
        )

        config = create_default_config()
        result, paths = run_analysis_pipeline(
            input_paths=[str(log_file)],
            config=config,
            format_override="python",
            export_formats={"json"},
        )

        assert result.total_events_parsed == 1

    def test_pipeline_incremental(self, tmp_path: Path):
        log_file = tmp_path / "test.log"
        log_file.write_text(
            "2026-01-01 12:00:00,000 ERROR [app] error\n",
            encoding="utf-8",
        )

        config = create_default_config()
        state_db = tmp_path / "state.db"

        # First run - records file in state store
        result1, _ = run_analysis_pipeline(
            input_paths=[str(log_file)],
            config=config,
            state_db_path=state_db,
            export_formats={"json"},
        )
        assert result1.total_events_parsed == 1

        # Second run with incremental - should skip unchanged file
        result2, _ = run_analysis_pipeline(
            input_paths=[str(log_file)],
            config=config,
            incremental=True,
            state_db_path=state_db,
            export_formats={"json"},
        )
        assert result2.total_files_skipped_incremental == 1

    def test_pipeline_run_id_format(self, tmp_path: Path):
        log_file = tmp_path / "test.log"
        log_file.write_text(
            "2026-01-01 12:00:00,000 INFO [app] started\n",
            encoding="utf-8",
        )

        config = create_default_config()
        result, _ = run_analysis_pipeline(
            input_paths=[str(log_file)],
            config=config,
            export_formats={"json"},
        )

        assert result.run_id.startswith("run-")
        assert len(result.run_id) > 10

    def test_pipeline_with_malformed_lines(self, tmp_path: Path):
        log_file = tmp_path / "mixed.log"
        log_file.write_text(
            "2026-01-01 12:00:00,000 INFO [app] good line\n"
            "this is not a valid log line\n"
            "2026-01-01 12:00:01,000 ERROR [app] another good line\n",
            encoding="utf-8",
        )

        config = create_default_config()
        result, _ = run_analysis_pipeline(
            input_paths=[str(log_file)],
            config=config,
            export_formats={"json"},
        )

        assert result.total_events_parsed == 2
        assert result.malformed_lines_count >= 1
