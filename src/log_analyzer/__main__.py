"""Command-line entry point for `python -m log_analyzer`."""

from __future__ import annotations

import sys

from log_analyzer.cli import main

if __name__ == "__main__":
    sys.exit(main())
