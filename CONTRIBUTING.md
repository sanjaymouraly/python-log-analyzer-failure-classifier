# Contributing to Python Log Analyzer & Failure Classifier

Thank you for your interest in contributing to `python-log-anomaly-analyzer`!

## Development Workflow

1. **Fork and Clone**:
   Clone the repository and create a virtual environment using Python 3.11+.
2. **Install Editable Package with Dev Dependencies**:
   ```bash
   pip install -e ".[dev]"
   ```
3. **Create a Feature or Fix Branch**:
   ```bash
   git checkout -b feat/your-feature-name
   ```
4. **Write Tests**:
   Add unit, regression, or CLI end-to-end tests under `tests/`. Ensure all assertions check concrete expected counts and classifications.
5. **Run Validation Suite**:
   ```bash
   ruff check src tests
   ruff format --check src tests
   mypy src/log_analyzer tests
   pytest --cov=log_analyzer --cov-report=term-missing
   ```
6. **Submit a Pull Request**:
   Provide a clear summary of the problem solved, verification steps, and any configuration or documentation updates.

## Code Standards

- **Python Version**: 3.11+ (`tomllib`, modern type hints `X | Y`).
- **Formatting & Linting**: Enforced via `ruff` (line length 100).
- **Type Safety**: Enforced via `mypy` (`disallow_untyped_defs = true`).
- **Security**: Never commit real production logs, credentials, API keys, or customer PII. Use synthetic test fixtures only.
