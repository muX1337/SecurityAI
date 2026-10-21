#!/usr/bin/env python
"""Fetch raw command-injection payload corpora into data/raw/ (optional — built-ins always available)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPOS = {
    "PayloadsAllTheThings": "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
}


def main() -> int:
    raw_dir = Path(__file__).resolve().parent.parent / "data" / "raw"
    raw_dir.mkdir(parents=True, exist_ok=True)

    for name, url in REPOS.items():
        dest = raw_dir / name
        if dest.exists():
            print(f"[skip] {dest} already exists")
            continue
        print(f"[clone] {url} -> {dest}")
        subprocess.check_call(["git", "clone", "--depth", "1", url, str(dest)])
    print("Done. Built-in payloads always available even without external corpora.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
