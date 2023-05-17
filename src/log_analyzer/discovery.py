"""File discovery, rotated log ordering, and bounded-memory streaming line reader."""

from __future__ import annotations

import glob
import gzip
import hashlib
import os
import re
from collections.abc import Iterator
from pathlib import Path

ROTATED_SUFFIX_PATTERN = re.compile(
    r"^(?P<base>.+?\.(?:log|txt|jsonl|out|err))(?:\.(?P<num>\d+))?(?:\.gz)?$",
    re.IGNORECASE,
)
SUPPORTED_EXTENSIONS = {".log", ".txt", ".jsonl", ".out", ".err", ".gz"}


def is_supported_log_file(path: Path) -> bool:
    """Return True if a file path matches supported log or rotated log naming conventions."""
    name_lower = path.name.lower()
    if name_lower.startswith("."):
        return False
    if any(name_lower.endswith(ext) for ext in SUPPORTED_EXTENSIONS):
        return True
    return bool(ROTATED_SUFFIX_PATTERN.match(name_lower))


def _rotation_sort_key(path: Path) -> tuple[str, int, str]:
    """Sort key that orders older rotated logs (e.g. app.log.2.gz, app.log.1) before active app.log."""
    match = ROTATED_SUFFIX_PATTERN.match(path.name)
    parent_str = str(path.parent)
    if match:
        base = match.group("base").lower()
        num_str = match.group("num")
        # Higher rotation number (.2) is older than (.1), which is older than active (0)
        rot_order = -int(num_str) if num_str is not None else 0
        return (f"{parent_str}/{base}", rot_order, path.name.lower())
    return (str(path).lower(), 0, path.name.lower())


def discover_log_files(
    inputs: list[str | Path],
    recursive: bool = True,
    file_filter: str | None = None,
) -> tuple[list[Path], list[str]]:
    """Discover log files from paths, directories, and glob patterns.

    Returns:
        Tuple of (sorted list of discovered Path objects, list of warning messages).
    """
    discovered: dict[str, Path] = {}
    warnings: list[str] = []
    filter_regex = re.compile(file_filter, re.IGNORECASE) if file_filter else None

    for raw_input in inputs:
        input_str = str(raw_input)
        candidate_path = Path(input_str)

        # Check if input is an existing file or directory first
        if candidate_path.exists():
            if candidate_path.is_file():
                resolved = str(candidate_path.resolve())
                if filter_regex and not filter_regex.search(candidate_path.name):
                    continue
                discovered[resolved] = candidate_path
            elif candidate_path.is_dir():
                try:
                    iterator = candidate_path.rglob("*") if recursive else candidate_path.glob("*")
                    for child in iterator:
                        try:
                            if child.is_file() and is_supported_log_file(child):
                                if filter_regex and not filter_regex.search(child.name):
                                    continue
                                discovered[str(child.resolve())] = child
                        except PermissionError as exc:
                            warnings.append(f"Permission denied accessing {child}: {exc}")
                except PermissionError as exc:
                    warnings.append(f"Permission denied scanning directory {candidate_path}: {exc}")
            continue

        # Check if it contains glob wildcards
        if any(ch in input_str for ch in ("*", "?", "[")):
            matched_paths = glob.glob(input_str, recursive=recursive)
            if not matched_paths:
                warnings.append(f"No files matched glob pattern: {input_str}")
            for matched in matched_paths:
                p = Path(matched)
                if p.is_file():
                    if filter_regex and not filter_regex.search(p.name):
                        continue
                    discovered[str(p.resolve())] = p
                elif p.is_dir():
                    sub_files, sub_warns = discover_log_files(
                        [p], recursive=recursive, file_filter=file_filter
                    )
                    warnings.extend(sub_warns)
                    for sf in sub_files:
                        discovered[str(sf.resolve())] = sf
        else:
            warnings.append(f"Input path does not exist: {input_str}")

    sorted_files = sorted(discovered.values(), key=_rotation_sort_key)
    return sorted_files, warnings


def compute_file_fingerprint(path: Path, sample_bytes: int = 65536) -> str:
    """Compute a fast content + metadata fingerprint for incremental processing."""
    stat = path.stat()
    hasher = hashlib.sha256()
    hasher.update(f"size:{stat.st_size}|mtime_ns:{stat.st_mtime_ns}|".encode())
    with path.open("rb") as fh:
        head = fh.read(sample_bytes)
        hasher.update(head)
        if stat.st_size > sample_bytes * 2:
            fh.seek(max(0, stat.st_size - sample_bytes))
            hasher.update(fh.read(sample_bytes))
    return hasher.hexdigest()


def stream_file_lines(path: Path, encoding: str = "utf-8") -> Iterator[tuple[int, str, bool]]:
    """Stream lines from a plain or gzip-compressed log file with bounded memory.

    Yields:
        Tuple of (1-based line_number, decoded_line_without_newline, had_encoding_error).
    """
    if not os.access(path, os.R_OK):
        raise PermissionError(f"Permission denied reading file: {path}")

    is_gzip = path.name.lower().endswith(".gz")

    if is_gzip:
        with gzip.open(path, "rb") as gz_fh:
            for line_num, raw_line in enumerate(gz_fh, start=1):
                yield _decode_raw_line(line_num, raw_line, encoding)
    else:
        with path.open("rb") as bin_fh:
            for line_num, raw_line in enumerate(bin_fh, start=1):
                # Guard against binary files with null bytes on any line
                if b"\x00" in raw_line:
                    raw_line = raw_line.replace(b"\x00", b"")
                    line_num_val, decoded, _ = _decode_raw_line(line_num, raw_line, encoding)
                    yield (line_num_val, decoded, True)
                    continue
                yield _decode_raw_line(line_num, raw_line, encoding)


def _decode_raw_line(line_num: int, raw_line: bytes, encoding: str) -> tuple[int, str, bool]:
    """Decode a raw byte line using the specified encoding, falling back gracefully on error."""
    had_error = False
    try:
        text = raw_line.decode(encoding, errors="strict")
    except (UnicodeDecodeError, LookupError):
        had_error = True
        fallback_enc = encoding if _is_valid_encoding(encoding) else "utf-8"
        text = raw_line.decode(fallback_enc, errors="replace")

    return line_num, text.rstrip("\r\n"), had_error


def _is_valid_encoding(encoding: str) -> bool:
    try:
        b"".decode(encoding)
        return True
    except LookupError:
        return False
