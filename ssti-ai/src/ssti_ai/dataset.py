"""SSTI dataset: JSONL pairs -> tokenized tensors with completion-only loss masking."""
from __future__ import annotations

import collections
import json
import random
from pathlib import Path

import torch
from torch.utils.data import Dataset

from .prompt import format_example, format_prompt


class SSTIDataset(Dataset):
    """Loads (context, payload) pairs from JSONL, tokenizes with prompt masking.

    Labels for prompt tokens are set to -100 (ignored by loss). Only the payload
    portion (after '### Payload:\\n') contributes to the loss.

    Args:
        jsonl_path: path to the JSONL file with (context, payload) pairs.
        tokenizer: a HuggingFace tokenizer.
        max_length: maximum token sequence length (truncation).
        max_per_context: if >0, cap pairs per context.id to this many (random
            sample with seed). Prevents high-volume contexts from drowning out
            sparse ones, encouraging context-conditional learning.
        seed: random seed for the per-context sampling.
    """

    def __init__(
        self,
        jsonl_path: Path,
        tokenizer,
        max_length: int = 256,
        max_per_context: int = 0,
        seed: int = 0,
    ):
        self.tokenizer = tokenizer
        self.max_length = max_length

        # Load all examples
        path = Path(jsonl_path)
        all_examples: list[dict] = []
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            all_examples.append(json.loads(line))

        # Apply per-context cap if requested
        if max_per_context > 0:
            rng = random.Random(seed)
            by_ctx: dict[str, list[dict]] = collections.defaultdict(list)
            for ex in all_examples:
                by_ctx[ex["context"]["id"]].append(ex)
            self.examples = []
            for group in by_ctx.values():
                if len(group) > max_per_context:
                    self.examples.extend(rng.sample(group, max_per_context))
                else:
                    self.examples.extend(group)
            rng.shuffle(self.examples)
        else:
            self.examples = all_examples

    def __len__(self) -> int:
        return len(self.examples)

    def __getitem__(self, idx: int) -> dict:
        pair = self.examples[idx]
        description = pair["context"]["description"]
        payload = pair["payload"]

        prompt_text = format_prompt(description)
        full_text = format_example(description, payload)

        # Tokenize prompt and full text separately to find the masking boundary.
        prompt_tokens = self.tokenizer(prompt_text, add_special_tokens=False)
        full_tokens = self.tokenizer(full_text + self.tokenizer.eos_token, add_special_tokens=False)

        input_ids = full_tokens["input_ids"][: self.max_length]
        attention_mask = full_tokens["attention_mask"][: self.max_length]

        # Mask: -100 for prompt tokens, real IDs for payload + EOS.
        prompt_len = len(prompt_tokens["input_ids"])
        boundary = min(prompt_len, len(input_ids))
        labels = [-100] * boundary + input_ids[boundary:]

        # Truncate labels to match the (possibly truncated) input_ids length.
        labels = labels[: len(input_ids)]

        return {
            "input_ids": input_ids,
            "attention_mask": attention_mask,
            "labels": labels,
        }


def create_data_collator(pad_token_id: int = 0):
    """Return a collate function that pads variable-length sequences in a batch."""
    def collate(batch: list[dict]) -> dict:
        max_len = max(len(item["input_ids"]) for item in batch)
        input_ids = []
        attention_mask = []
        labels = []
        for item in batch:
            pad_len = max_len - len(item["input_ids"])
            input_ids.append(item["input_ids"] + [pad_token_id] * pad_len)
            attention_mask.append(item["attention_mask"] + [0] * pad_len)
            labels.append(item["labels"] + [-100] * pad_len)
        return {
            "input_ids": torch.tensor(input_ids, dtype=torch.long),
            "attention_mask": torch.tensor(attention_mask, dtype=torch.long),
            "labels": torch.tensor(labels, dtype=torch.long),
        }
    return collate
