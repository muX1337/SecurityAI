"""Inference: load the fine-tuned model and generate XSS payloads for a context."""
from __future__ import annotations

import torch
from peft import PeftModel
from transformers import AutoModelForCausalLM, AutoTokenizer

from .prompt import extract_payload, format_prompt
from .train import MODEL_ID

GENERATION_DEFAULTS = {
    "max_new_tokens": 128,
    "strategies": ("greedy", "sampling"),
    "temperature": 0.7,
    "top_p": 0.9,
}


def load_model(adapter_path: str | None = None, use_4bit: bool = False):
    """Load the model for inference.

    adapter_path can be:
      - None: load the base Qwen2.5-1.5B model only (for baseline comparison).
      - A LoRA adapter dir (has adapter_config.json): load base + merge adapter.
      - A merged model dir (has config.json but no adapter_config.json): load directly.
    """
    from pathlib import Path

    model_kwargs = {"dtype": torch.bfloat16}
    if use_4bit:
        from transformers import BitsAndBytesConfig
        model_kwargs["quantization_config"] = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=torch.bfloat16,
        )

    if adapter_path:
        p = Path(adapter_path)
        is_merged = (p / "config.json").exists() and not (p / "adapter_config.json").exists()
        if is_merged:
            # Standalone merged model — load directly, no adapter needed.
            tokenizer = AutoTokenizer.from_pretrained(adapter_path)
            if tokenizer.pad_token is None:
                tokenizer.pad_token = tokenizer.eos_token
            model = AutoModelForCausalLM.from_pretrained(adapter_path, **model_kwargs)
            print(f"[generate] loaded merged model from {adapter_path}")
        else:
            # LoRA adapter — load base, apply adapter, merge.
            tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
            if tokenizer.pad_token is None:
                tokenizer.pad_token = tokenizer.eos_token
            model = AutoModelForCausalLM.from_pretrained(MODEL_ID, **model_kwargs)
            model = PeftModel.from_pretrained(model, adapter_path)
            model = model.merge_and_unload()
            print(f"[generate] merged adapter from {adapter_path}")
    else:
        tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
        if tokenizer.pad_token is None:
            tokenizer.pad_token = tokenizer.eos_token
        model = AutoModelForCausalLM.from_pretrained(MODEL_ID, **model_kwargs)

    model.eval()
    return model, tokenizer


def generate(
    model,
    tokenizer,
    description: str,
    strategy: str = "greedy",
    n: int = 1,
    max_new_tokens: int = 128,
    temperature: float = 0.7,
    top_p: float = 0.9,
) -> list[str]:
    """Generate n payload candidates for the given context description.

    strategy: 'greedy' (deterministic, for eval) or 'sampling' (diverse, for interactive).
    Returns a list of extracted payload strings (may contain duplicates or None filtered out).
    """
    prompt = format_prompt(description)
    inputs = tokenizer(prompt, return_tensors="pt").to(model.device)

    payloads: list[str] = []
    for _ in range(n):
        if strategy == "greedy":
            out = model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                do_sample=False,
                eos_token_id=tokenizer.eos_token_id,
            )
        else:
            out = model.generate(
                **inputs,
                max_new_tokens=max_new_tokens,
                do_sample=True,
                temperature=temperature,
                top_p=top_p,
                eos_token_id=tokenizer.eos_token_id,
            )
        raw = tokenizer.decode(out[0], skip_special_tokens=True)
        payload = parse_generation_output(raw)
        if payload:
            payloads.append(payload)

    return payloads


def parse_generation_output(raw_text: str) -> str | None:
    """Extract the payload from a model generation (delegates to prompt.extract_payload)."""
    return extract_payload(raw_text)
