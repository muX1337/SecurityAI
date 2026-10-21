#!/usr/bin/env python
"""Train OpenRedirect payload generation model via LoRA on the OpenRedirect dataset."""
from __future__ import annotations

import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from openredirect_ai.train import TrainConfig, train


def main() -> int:
    _version = os.environ.get("RETRAIN_VERSION") or "redirect-qwen1.5b-v1"
    config = TrainConfig(
        train_path=str(ROOT / "data" / "pairs" / "train.jsonl"),
        val_path=str(ROOT / "data" / "pairs" / "val.jsonl"),
        output_dir=str(ROOT / "models" / _version),
    )
    print(f"[config] {config}")
    train(config)
    print("[done] training complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
