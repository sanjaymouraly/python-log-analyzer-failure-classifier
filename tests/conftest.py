"""Shared pytest fixtures for the Python Log Analyzer test suite."""

from __future__ import annotations

from pathlib import Path

import pytest

from log_analyzer.config import AnalyzerConfig, create_default_config
from log_analyzer.security import SecretRedactor


@pytest.fixture
def default_config() -> AnalyzerConfig:
    """Return a fresh default AnalyzerConfig instance."""
    return create_default_config()


@pytest.fixture
def default_redactor(default_config: AnalyzerConfig) -> SecretRedactor:
    """Return a SecretRedactor configured with default rules."""
    return SecretRedactor(default_config.security)


@pytest.fixture
def sample_logs_dir(tmp_path: Path) -> Path:
    """Return a temporary directory for test log files."""
    d = tmp_path / "logs"
    d.mkdir(parents=True, exist_ok=True)
    return d
