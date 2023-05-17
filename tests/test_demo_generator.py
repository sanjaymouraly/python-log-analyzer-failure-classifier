"""Unit tests for the synthetic demo data generator."""

from __future__ import annotations

from pathlib import Path

from log_analyzer.demo_generator import generate_demo_dataset, generate_scale_log_file


class TestGenerateDemoDataset:
    def test_creates_expected_files(self, tmp_path: Path):
        manifest = generate_demo_dataset(tmp_path, seed=42)
        assert len(manifest.files_created) == 7
        for filename in manifest.files_created:
            assert (tmp_path / filename).exists()

    def test_expected_event_counts(self, tmp_path: Path):
        manifest = generate_demo_dataset(tmp_path, seed=42)
        assert manifest.expected_total_events > 0
        assert manifest.expected_error_events > 0
        assert manifest.expected_warning_events > 0
        assert manifest.expected_info_events > 0

    def test_deterministic_with_same_seed(self, tmp_path: Path):
        manifest1 = generate_demo_dataset(tmp_path / "run1", seed=42)
        manifest2 = generate_demo_dataset(tmp_path / "run2", seed=42)
        assert manifest1.expected_total_events == manifest2.expected_total_events
        assert manifest1.expected_error_events == manifest2.expected_error_events

    def test_different_seeds_produce_different_data(self, tmp_path: Path):
        dir1 = tmp_path / "run1"
        dir2 = tmp_path / "run2"
        manifest1 = generate_demo_dataset(dir1, seed=42)
        manifest2 = generate_demo_dataset(dir2, seed=99)
        # The actual file contents should differ (different random messages/IDs)
        # Use .log files (not .gz) to avoid binary comparison issues
        log_files1 = [f for f in manifest1.files_created if f.endswith(".log")]
        log_files2 = [f for f in manifest2.files_created if f.endswith(".log")]
        file1 = dir1 / log_files1[0]
        file2 = dir2 / log_files2[0]
        assert file1.read_text(encoding="utf-8") != file2.read_text(encoding="utf-8")

    def test_expected_anomaly_windows(self, tmp_path: Path):
        manifest = generate_demo_dataset(tmp_path, seed=42, include_spikes=True)
        assert len(manifest.expected_anomaly_windows) >= 1

    def test_no_spikes_option(self, tmp_path: Path):
        manifest = generate_demo_dataset(tmp_path, seed=42, include_spikes=False)
        assert isinstance(manifest.expected_anomaly_windows, list)

    def test_expected_category_counts(self, tmp_path: Path):
        manifest = generate_demo_dataset(tmp_path, seed=42)
        assert len(manifest.expected_category_counts) > 0
        assert all(v > 0 for v in manifest.expected_category_counts.values())

    def test_to_dict(self, tmp_path: Path):
        manifest = generate_demo_dataset(tmp_path, seed=42)
        d = manifest.to_dict()
        assert "output_dir" in d
        assert "seed" in d
        assert "files_created" in d
        assert "expected_total_events" in d

    def test_creates_gzip_file(self, tmp_path: Path):
        manifest = generate_demo_dataset(tmp_path, seed=42)
        gz_files = [f for f in manifest.files_created if f.endswith(".gz")]
        assert len(gz_files) >= 1

    def test_creates_jsonl_file(self, tmp_path: Path):
        manifest = generate_demo_dataset(tmp_path, seed=42)
        jsonl_files = [f for f in manifest.files_created if f.endswith(".jsonl")]
        assert len(jsonl_files) >= 1

    def test_creates_rotated_logs(self, tmp_path: Path):
        manifest = generate_demo_dataset(tmp_path, seed=42)
        rotated = [f for f in manifest.files_created if ".log." in f]
        assert len(rotated) >= 1

    def test_malformed_lines_included(self, tmp_path: Path):
        manifest = generate_demo_dataset(tmp_path, seed=42)
        assert manifest.expected_malformed_lines > 0

    def test_missing_timestamp_events(self, tmp_path: Path):
        manifest = generate_demo_dataset(tmp_path, seed=42)
        assert manifest.expected_missing_timestamp_events >= 0


class TestGenerateScaleLogFile:
    def test_creates_file(self, tmp_path: Path):
        log_file = tmp_path / "scale.log"
        result = generate_scale_log_file(log_file, event_count=1000, seed=99)
        assert result.exists()

    def test_event_count(self, tmp_path: Path):
        log_file = tmp_path / "scale.log"
        generate_scale_log_file(log_file, event_count=5000, seed=99)
        with open(log_file) as f:
            lines = f.readlines()
        assert len(lines) == 5000

    def test_deterministic(self, tmp_path: Path):
        log_file1 = tmp_path / "scale1.log"
        log_file2 = tmp_path / "scale2.log"
        generate_scale_log_file(log_file1, event_count=1000, seed=99)
        generate_scale_log_file(log_file2, event_count=1000, seed=99)
        assert log_file1.read_text() == log_file2.read_text()

    def test_different_seeds(self, tmp_path: Path):
        log_file1 = tmp_path / "scale1.log"
        log_file2 = tmp_path / "scale2.log"
        generate_scale_log_file(log_file1, event_count=1000, seed=99)
        generate_scale_log_file(log_file2, event_count=1000, seed=42)
        assert log_file1.read_text() != log_file2.read_text()

    def test_file_has_errors(self, tmp_path: Path):
        log_file = tmp_path / "scale.log"
        generate_scale_log_file(log_file, event_count=10000, seed=99)
        content = log_file.read_text()
        assert "ERROR" in content

    def test_file_has_info(self, tmp_path: Path):
        log_file = tmp_path / "scale.log"
        generate_scale_log_file(log_file, event_count=10000, seed=99)
        content = log_file.read_text()
        assert "INFO" in content
