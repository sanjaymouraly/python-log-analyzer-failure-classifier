# Development & Testing Guide

## Setting Up a Development Environment

### Linux / macOS (Bash)

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

### Windows (PowerShell)

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

## Running Quality Checks

1. **Run the complete test suite with coverage enforcement ($\ge 85\%$):**

```bash
pytest --cov=log_analyzer --cov-report=term-missing
```

2. **Run the 100,000-event performance smoke test with benchmark output:**

```bash
pytest tests/test_performance_scale.py -s
```

3. **Run Ruff linter and formatter checks:**

```bash
ruff check src tests
ruff format --check src tests
```

4. **Run Mypy static type checking:**

```bash
mypy src/log_analyzer tests
```

## Adding a New Log Parser

1. Add the compiled header regular expression and `_parse_<format>_line()` helper in `src/log_analyzer/parsers.py`.
2. Register the format identifier in `VALID_FORMATS` in `src/log_analyzer/config.py`.
3. Add unit and streaming integration tests in `tests/test_parsers.py`.
4. Document the format with examples in `docs/supported-formats.md`.
