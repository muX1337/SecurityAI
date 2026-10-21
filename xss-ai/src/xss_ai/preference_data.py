"""Preference data formatting for DPO training.

Converts (context description, chosen payload, rejected payload) tuples into
the {"prompt", "chosen", "rejected"} dict format that TRL's DPOTrainer expects.
"""
from __future__ import annotations

import json
from pathlib import Path

from .prompt import format_prompt


def format_for_dpo(description: str, chosen: str, rejected: str) -> dict:
    """Format a preference pair for DPOTrainer.

    Args:
        description: the context description (natural-language prompt body).
        chosen: the payload that fires in a browser (preferred).
        rejected: the payload that does NOT fire (dispreferred).

    Returns:
        {"prompt": str, "chosen": str, "rejected": str}
    """
    return {
        "prompt": format_prompt(description),
        "chosen": chosen,
        "rejected": rejected,
    }


def load_preference_pairs(jsonl_path: Path) -> list[dict]:
    """Load preference pairs from a JSONL file.

    Each line must be a JSON object with "prompt", "chosen", "rejected" keys.
    """
    pairs: list[dict] = []
    for line in Path(jsonl_path).read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        pairs.append(json.loads(line))
    return pairs
