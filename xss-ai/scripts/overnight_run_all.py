#!/usr/bin/env python
"""Overnight master script: runs DPO pair generation + hard-context mining.

Run this before going to sleep. It executes:
  1. DPO preference pair generation (500+ pairs, resumable)
  2. Hard-context browser mining (payloads for 0% contexts)

Both jobs are resumable — if interrupted, re-run this script and it picks
up from the last checkpoint.

Usage:
    cd E:\\Documents\\Playground\\xss-ai
    .venv-ml\\Scripts\\python.exe scripts\\overnight_run_all.py
"""
from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENV_PYTHON = str(ROOT / ".venv-ml" / "Scripts" / "python.exe")


def run_job(name: str, script: str) -> bool:
    """Run a job script. Returns True on success."""
    print(f"\n{'='*60}")
    print(f"[master] STARTING: {name}")
    print(f"{'='*60}\n")

    start = time.time()
    result = subprocess.run(
        [VENV_PYTHON, str(ROOT / "scripts" / script)],
        cwd=str(ROOT),
    )
    elapsed = time.time() - start

    status = "SUCCESS" if result.returncode == 0 else f"EXIT {result.returncode}"
    print(f"\n[master] {name}: {status} ({elapsed/60:.1f} min)")
    return result.returncode == 0


def main() -> int:
    print("[master] ExploitGym Overnight Job Runner")
    print(f"[master] Time: {time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[master] Python: {VENV_PYTHON}")
    print()

    total_start = time.time()

    # Job 1: DPO preference pairs
    ok1 = run_job(
        "DPO Preference Pair Generation (500+ pairs)",
        "overnight_1_dpo_pairs.py",
    )

    # Job 2: Hard-context mining
    ok2 = run_job(
        "Hard-Context Browser Mining (escape/strip/attr/url)",
        "overnight_2_mine_hard.py",
    )

    # Summary
    elapsed = time.time() - total_start
    print(f"\n{'='*60}")
    print(f"[master] ALL JOBS COMPLETE ({elapsed/60:.1f} min total)")
    print(f"  Job 1 (DPO pairs):      {'✅' if ok1 else '❌'}")
    print(f"  Job 2 (Hard mining):    {'✅' if ok2 else '❌'}")
    print(f"{'='*60}")

    # Check outputs
    dpo_file = ROOT / "data" / "pairs" / "dpo" / "preference_pairs.jsonl"
    hard_file = ROOT / "data" / "pairs" / "hard_context_payloads.jsonl"

    if dpo_file.exists():
        count = sum(1 for _ in dpo_file.read_text().splitlines() if _.strip())
        print(f"\n[master] DPO pairs: {count}")
    if hard_file.exists():
        count = sum(1 for _ in hard_file.read_text().splitlines() if _.strip())
        print(f"[master] Hard-context payloads: {count}")

    print("\n[master] NEXT STEPS (when you wake up):")
    print("  1. Check DPO pair count — if 500+, run DPO training:")
    print("     python scripts/13_train_dpo.py")
    print("  2. Merge hard-context payloads into clean dataset:")
    print("     cat data/pairs/hard_context_payloads.jsonl >> data/pairs/clean/pairs_raw.jsonl")
    print("     python scripts/07_build_clean_dataset.py --resume")
    print("  3. Retrain XSS model with expanded data:")
    print("     python scripts/08_train.py")
    print("  4. Evaluate:")
    print("     python scripts/10_evaluate.py")

    return 0


if __name__ == "__main__":
    sys.exit(main())
