"""Brand guard: scan repo files for real-company names.

Real names are stored ONLY as SHA-256 hashes, never in plain text, so
this script itself cannot leak them. It hashes every word and every
adjacent word pair in each scanned file and compares against the hash
set. Run: python3 scripts/brand_check.py
"""

from __future__ import annotations

import hashlib
import itertools
import re
import sys
from pathlib import Path

# SHA-256 hashes of real-company names (never stored in plain text).
BLOCKLIST_HASHES = {
    "74c860f63661b29cd747cf485fb26898163066cb84328f3855f877dbbeef5d56",
    "33860d208be29fde5630eaa145e2c2e28160e7ad096183c370a7fa2ef6a6c852",
    "0a1f951fe72682bfd0c23fb6e1a8bf56cc36577cc69b7a36f86b22ddf06d454e",
    "b0126946c556dc47a63edd3ba7ab3671ef0a46c22d51775debc63291b510fccc",
    "38e0c90a73bd834832b7b4ecd6c9a3488d3d6bc46e49ab40c29b60767e502814",
    "64686f98a42da48751847c2311865f1588d1d2e3b2575d2cf08b5d5799d2abd0",
    "e5f2f4ada0333086bcc638d7a9326b77bf5cf9b42fb402001734639f860fa53b",
    "4a3892e5bc960fe49946b5f81ed92323657fb35aaaed25f0e65d91ba9187b5aa",
    "9ccfe0b5c67275792b5baa250e5fe58e4d618418b353effc55dd322a59efb9fd",
    "4cbe0ca084805760aae8a3ca0aaa33828cc271235c8ab3c97c438ab33aef701e",
    "5a3cd73b85330e5fb4a0e74e8f8c0e9a65a44422f65aa5d4daca31df45f110b4",
    "479d0a486a92e55c156ea1cb76c68c68a92b577fd6b403b7c7484bcecdc3d1f5",
    "5ba14c9c0738b2e6450ed1c25f0ad21336f29ee2a4fb83051555a4a6ac6162f1",
    "877d41bc540c57e06ac1f4d3edfd59e5d3651402500a4336e26f50572fcb9389",
}

SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", ".venv"}
SCAN_SUFFIXES = {".py", ".md", ".txt", ".toml", ".cfg"}


def _hashes_for(text: str):
    words = re.findall(r"[a-z]+", text.lower())
    candidates = list(words) + [" ".join(pair) for pair in itertools.pairwise(words)]
    return {hashlib.sha256(candidate.encode()).hexdigest() for candidate in candidates}


def find_violations(path: Path):
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return sorted(_hashes_for(text) & BLOCKLIST_HASHES)


def scan_paths(root: Path):
    violations = {}
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix not in SCAN_SUFFIXES:
            continue
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        found = find_violations(path)
        if found:
            violations[str(path)] = found
    return violations


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    violations = scan_paths(root)
    if violations:
        for path, hashes in violations.items():
            print(f"BLOCKLISTED NAME HASH FOUND in {path}: {hashes}")
        return 1
    print("brand check passed: no blocklisted names found")
    return 0


if __name__ == "__main__":
    sys.exit(main())
