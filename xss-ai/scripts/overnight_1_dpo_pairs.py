#!/usr/bin/env python
"""Overnight job 1: Generate 500+ XSS DPO preference pairs.

Runs the preference pair generation with 16 candidates per context,
resumable via checkpoint. Targets all 48 training contexts.

Usage:
    python scripts/overnight_1_dpo_pairs.py
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

def main() -> int:
    print("[overnight-1] Starting DPO preference pair generation")
    print("[overnight-1] Target: 500+ pairs from 48 contexts, 16 candidates each")

    # Reset checkpoint to start fresh with higher candidate count
    subprocess.run(
        [str(ROOT / ".venv-ml" / "Scripts" / "python.exe"),
         str(ROOT / "scripts" / "12_generate_preferences.py"),
         "--candidates", "16",
         "--max-pairs-per-context", "15",
         "--resume",  # resume from existing checkpoint if any
         "--seed", "123",  # different seed for diversity
        ],
        cwd=str(ROOT),
        capture_output=False,
    )

    # Check final pair count
    pairs_file = ROOT / "data" / "pairs" / "dpo" / "preference_pairs.jsonl"
    if pairs_file.exists():
        count = sum(1 for _ in pairs_file.read_text().splitlines() if _.strip())
        print(f"\n[overnight-1] DONE: {count} preference pairs generated")
        if count >= 500:
            print("[overnight-1] SUCCESS: target of 500+ pairs met!")
        else:
            print(f"[overnight-1] WARNING: only {count} pairs (target was 500)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
