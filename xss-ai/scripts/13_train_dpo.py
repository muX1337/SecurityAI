#!/usr/bin/env python
"""Train XSS model with DPO on preference pairs."""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from xss_ai.dpo_train import DPOTrainConfig, train_dpo


def main() -> int:
    config = DPOTrainConfig(
        pref_path=str(ROOT / "data" / "pairs" / "dpo" / "preference_pairs.jsonl"),
        output_dir=str(ROOT / "models" / "xss-qwen1.5b-dpo"),
        sft_model_path=str(ROOT / "models" / "xss-qwen1.5b-v2" / "merged"),
    )
    print(f"[config] {config}")
    train_dpo(config)
    print("[done] DPO training complete")
    return 0


if __name__ == "__main__":
    sys.exit(main())
