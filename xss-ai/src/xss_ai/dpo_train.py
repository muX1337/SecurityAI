"""DPO (Direct Preference Optimization) training for the XSS payload model.

Refines the SFT model by pushing it toward payloads that fire in browsers
(chosen) and away from those that don't (rejected). The browser oracle is
the implicit reward signal captured in the preference dataset.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import torch
from datasets import Dataset
from peft import LoraConfig, TaskType
from transformers import AutoModelForCausalLM, AutoTokenizer
from trl import DPOConfig, DPOTrainer

from .preference_data import load_preference_pairs
from .train import LORA_TARGETS


@dataclass
class DPOTrainConfig:
    pref_path: str = "data/pairs/dpo/preference_pairs.jsonl"
    output_dir: str = "models/xss-qwen1.5b-dpo"
    sft_model_path: str = "models/xss-qwen1.5b-v2/merged"
    epochs: int = 1
    learning_rate: float = 1e-5
    batch_size: int = 4
    grad_accum_steps: int = 2
    beta: float = 0.2
    max_length: int = 256
    warmup_ratio: float = 0.1
    lora_rank: int = 32
    lora_alpha: int = 64
    lora_dropout: float = 0.05


def train_dpo(config: DPOTrainConfig):
    """Run DPO training on the preference dataset."""
    output_dir = Path(config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load tokenizer + model (the SFT merged model as the starting point)
    tokenizer = AutoTokenizer.from_pretrained(config.sft_model_path)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    print(f"[dpo] loading SFT model from {config.sft_model_path}...")
    model = AutoModelForCausalLM.from_pretrained(
        config.sft_model_path, dtype=torch.bfloat16
    )
    model.config.use_cache = False
    if torch.cuda.is_available():
        model = model.to("cuda")

    # LoRA config
    peft_config = LoraConfig(
        task_type=TaskType.CAUSAL_LM,
        r=config.lora_rank,
        lora_alpha=config.lora_alpha,
        lora_dropout=config.lora_dropout,
        target_modules=LORA_TARGETS,
    )

    # Load preference data
    pairs = load_preference_pairs(config.pref_path)
    print(f"[dpo] loaded {len(pairs)} preference pairs")
    dataset = Dataset.from_list(pairs)

    # DPO config.
    # NOTE: TRL 1.8.0's DPOConfig only exposes `max_length` (total sequence
    # length, truncated via `truncation_mode`, default "keep_start"); there is
    # no separate `max_prompt_length`/`max_completion_length` field, so we do
    # not pass one. Set max_length generously relative to expected prompt+payload.
    dpo_config = DPOConfig(
        output_dir=str(output_dir),
        num_train_epochs=config.epochs,
        per_device_train_batch_size=config.batch_size,
        gradient_accumulation_steps=config.grad_accum_steps,
        learning_rate=config.learning_rate,
        beta=config.beta,
        max_length=config.max_length,
        warmup_ratio=config.warmup_ratio,
        lr_scheduler_type="cosine",
        bf16=True,
        logging_steps=10,
        save_strategy="epoch",
        save_total_limit=3,
        report_to="none",
        gradient_checkpointing=True,
        remove_unused_columns=False,
    )

    # DPO trainer
    trainer = DPOTrainer(
        model=model,
        args=dpo_config,
        train_dataset=dataset,
        processing_class=tokenizer,
        peft_config=peft_config,
    )

    print("[dpo] starting DPO training...")
    trainer.train()

    # Save final adapter
    final_dir = output_dir / "final"
    trainer.model.save_pretrained(str(final_dir))
    tokenizer.save_pretrained(str(final_dir))
    print(f"[dpo] saved final adapter to {final_dir}")

    return trainer
