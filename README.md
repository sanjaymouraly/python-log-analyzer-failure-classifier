# Python Log Analyzer & Failure Classifier

Parses application logs, classifies failures, and highlights anomalies and recurring error patterns.

## Features

- Streams multi-format logs (.log, .txt, .jsonl, .gz) with bounded memory.
- Parses Python logging, JSON, syslog, and common application log formats.
- Orders rotated log families chronologically and removes duplicate boundary records.
- Classifies failures into stable fingerprints and categories.
- Detects anomaly spikes against a rolling baseline.
- Generates standalone HTML reports and charts.
- Supports incremental runs with a SQLite state database.

## Stack

Python, pandas, Matplotlib

## Clone

```bash
git clone https://github.com/sanjaymouraly/python-log-analyzer-failure-classifier.git
cd python-log-analyzer-failure-classifier
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
python -m pip install --upgrade pip
pip install -e ".[dev]"
```

## Run

```bash
log-analyzer --help
```

## Tests

```bash
pytest -q
```

## Notes

- Sample data, when included, is synthetic.

## License

MIT © 2023 [Sanjay Mouraly](https://github.com/sanjaymouraly)
