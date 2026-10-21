# ssrf-ai

Context-aware SSRF payload generation model. Fine-tuned Qwen2.5-1.5B that generates SSRF URL payloads for a given injection context.

## Results

| Metric | Rate | Target | Status |
|--------|------|--------|--------|
| T1 Synthetic (callback success) | 96.9% | 60% | ✅ |
| T2 Held-out filter combos | 60.0% | 30% | ✅ |
| Valid URL rate | 100% | 90% | ✅ |
| Diversity | 0.80 | 0.70 | ✅ |
| Refusal rate | 0% | ~0% | ✅ |

## Quickstart

```bash
python -m venv .venv-ml && source .venv-ml/Scripts/activate
pip install -e ".[dev]"
pip install torch transformers peft accelerate trl datasets httpx flask
# For CUDA: pip install torch==2.11.0+cu128 --index-url https://download.pytorch.org/whl/cu128

# Build dataset:
python scripts/02_build_pairs.py       # filter harness -> pairs_raw.jsonl
python scripts/04_finalize_splits.py   # split + quality gates -> train/val/test.jsonl

# Train:
python scripts/05_train.py             # QLoRA LoRA on Qwen2.5-1.5B

# Evaluate:
python scripts/07_evaluate.py          # T1/T2/metrics

# Generate payloads:
python scripts/06_generate.py "Server fetches URL from query param, blocks private IPs"
```

## Architecture

- **Context → payload** generation (same as xss-ai)
- **Callback oracle**: mock server + HTTP listener — the SSRF ground truth
- **Filter harness**: 7 URL filters (IP blocking, scheme allowlist, redirect policy, etc.)
- **Training data**: 935 pairs from 21 contexts × 65 payloads
- **Model**: Qwen2.5-1.5B, bf16 LoRA (rank 32), 5 epochs

## Layout

- `src/ssrf_ai/` — pipeline + ML modules
- `src/ssrf_ai/oracle/` — callback oracle (listener + mock server + check_fires)
- `src/ssrf_ai/eval/` — eval harness (T1/T2/metrics/report)
- `src/labs/` — T3 vulnerable Flask app (Docker-ready)
- `data/contexts/ssrf_contexts.yaml` — context taxonomy (21 contexts)
- `scripts/` — numbered pipeline entry points
