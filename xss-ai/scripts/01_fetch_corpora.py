#!/usr/bin/env python
"""Fetch raw XSS corpora into data/raw/ via git clone (shallow)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

REPOS = {
    "SecLists": "https://github.com/danielmiessler/SecLists.git",
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
        subprocess.check_call(
            ["git", "clone", "--depth", "1", url, str(dest)]
        )
    print("Done. Corpora in", raw_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
