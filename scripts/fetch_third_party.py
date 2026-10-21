#!/usr/bin/env python
"""Fetch the third-party corpora the training pipelines consume.

These repos are deliberately NOT committed (see root .gitignore):
size, licensing, and they are someone else's projects.

Usage (from the SecurityAI root):
    python scripts/fetch_third_party.py            # SecLists + PayloadsAllTheThings
    python scripts/fetch_third_party.py --cape     # additionally clone CAPE sandbox
"""
from __future__ import annotations

import argparse
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

TARGETS = [
    {
        "name": "SecLists",
        "url": "https://github.com/danielmiessler/SecLists.git",
        "dest": ROOT / "xss-ai" / "data" / "raw" / "SecLists",
        "used_by": "payload mining (01_collect)",
    },
    {
        "name": "PayloadsAllTheThings",
        "url": "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
        "dest": ROOT / "xss-ai" / "data" / "raw" / "PayloadsAllTheThings",
        "used_by": "payload mining (01_collect)",
    },
]

CAPE = {
    "name": "CAPE sandbox",
    "url": "https://github.com/kevoreilly/CAPEv2.git",
    "dest": ROOT / "malware-lab" / "cape",
    "used_by": "malware-lab dynamic analysis",
}


def clone(name: str, url: str, dest: Path) -> None:
    if dest.exists() and any(dest.iterdir()):
        print(f"[skip] {name} already present at {dest}")
        return
    print(f"[clone] {name} → {dest}")
    result = subprocess.run(
        ["git", "clone", "--depth", "1", url, str(dest)],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"[error] {name}: {result.stderr.strip()}", file=sys.stderr)
        sys.exit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cape", action="store_true",
                        help="also clone the CAPE sandbox (large)")
    args = parser.parse_args()

    targets = TARGETS + ([CAPE] if args.cape else [])
    for t in targets:
        clone(t["name"], t["url"], t["dest"])
        print(f"       used by: {t['used_by']}")
    print("\ndone.")


if __name__ == "__main__":
    main()
