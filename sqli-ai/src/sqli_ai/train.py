"""QLoRA fine-tuning of Qwen2.5-1.5B on browser-verified XSS pairs."""
from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

import torch
from peft import LoraConfig, TaskType, get_peft_model
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    Trainer,
    TrainingArguments,
)

from .dataset import SQLiDataset, create_data_collator

MODEL_ID = os.environ.get("BASE_MODEL_ID", "Qwen/Qwen2.5-1.5B")  # override via env for retrain-all

# LoRA target modules for Qwen2.5 (all linear projections)
LORA_TARGETS = ["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"]


@dataclass
class TrainConfig:
    train_path: str = "data/pairs/clean/train.jsonl"
    val_path: str = "data/pairs/clean/val.jsonl"
    output_dir: str = "models/sqli-qwen1.5b-v1"
    epochs: int = 5
    learning_rate: float = 1e-4
    batch_size: int = 8
    grad_accum_steps: int = 4
    max_length: int = 256
    warmup_ratio: float = 0.03
    weight_decay: float = 0.01
    lora_rank: int = 32
    lora_alpha: int = 64
    lora_dropout: float = 0.05
    save_steps_ratio: float = 0.5  # save every 0.5 epoch
    use_4bit: bool = False  # bitsandbytes not available on Windows; bf16 LoRA fits in 12GB
    max_per_context: int = 50  # balance training data across contexts


def load_model_and_tokenizer(config: TrainConfig):
    """Load Qwen2.5-1.5B tokenizer + model. Uses 4-bit if available."""
    tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    model_kwargs = {"dtype": torch.bfloat16}

    if config.use_4bit:
        try:
            import bitsandbytes  # noqa: F401 — verify it's actually installed
            from transformers import BitsAndBytesConfig
            bnb_config = BitsAndBytesConfig(
                load_in_4bit=True,
                bnb_4bit_quant_type="nf4",
                bnb_4bit_compute_dtype=torch.bfloat16,
                bnb_4bit_use_double_quant=True,
            )
            model_kwargs["quantization_config"] = bnb_config
            print("[model] loading in 4-bit (QLoRA)")
        except Exception as e:
            print(f"[model] 4-bit unavailable ({e}), falling back to bf16 LoRA")
            config.use_4bit = False

    model = AutoModelForCausalLM.from_pretrained(MODEL_ID, **model_kwargs)
    model.config.use_cache = False

    # Move to GPU if not quantized (quantized models manage their own device)
    if not config.use_4bit and torch.cuda.is_available():
        model = model.to("cuda")
        print(f"[model] moved to {torch.cuda.get_device_name(0)}")

    return model, tokenizer


def apply_lora(model, config: TrainConfig):
    """Attach LoRA adapters to the model."""
    lora_config = LoraConfig(
        task_type=TaskType.CAUSAL_LM,
        r=config.lora_rank,
        lora_alpha=config.lora_alpha,
        lora_dropout=config.lora_dropout,
        target_modules=LORA_TARGETS,
    )
    model = get_peft_model(model, lora_config)
    model.print_trainable_parameters()
    return model


def train(config: TrainConfig):
    """Full training run: load model, create datasets, train, save."""
    output_dir = Path(config.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    # Load model + tokenizer
    model, tokenizer = load_model_and_tokenizer(config)
    model = apply_lora(model, config)

    # Create datasets (with per-context balancing for train)
    train_ds = SQLiDataset(config.train_path, tokenizer, max_length=config.max_length,
                          max_per_context=config.max_per_context)
    val_ds = SQLiDataset(config.val_path, tokenizer, max_length=config.max_length)
    print(f"[data] train={len(train_ds)}, val={len(val_ds)}")

    collator = create_data_collator(pad_token_id=tokenizer.pad_token_id)

    # Calculate save steps (every 0.5 epoch)
    steps_per_epoch = len(train_ds) // (config.batch_size * config.grad_accum_steps)
    save_steps = max(1, int(steps_per_epoch * config.save_steps_ratio))

    training_args = TrainingArguments(
        output_dir=str(output_dir),
        num_train_epochs=config.epochs,
        per_device_train_batch_size=config.batch_size,
        per_device_eval_batch_size=config.batch_size,
        gradient_accumulation_steps=config.grad_accum_steps,
        learning_rate=config.learning_rate,
        lr_scheduler_type="cosine",
        warmup_ratio=config.warmup_ratio,
        weight_decay=config.weight_decay,
        bf16=True,
        logging_steps=10,
        eval_strategy="steps",
        eval_steps=save_steps,
        save_steps=save_steps,
        save_total_limit=10,
        load_best_model_at_end=False,
        report_to="none",
        gradient_checkpointing=True,
    )

    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=train_ds,
        eval_dataset=val_ds,
        data_collator=collator,
    )

    print("[train] starting training...")
    trainer.train()

    # Save final adapter
    final_dir = output_dir / "final"
    model.save_pretrained(str(final_dir))
    tokenizer.save_pretrained(str(final_dir))
    print(f"[train] saved final adapter to {final_dir}")

    return trainer
