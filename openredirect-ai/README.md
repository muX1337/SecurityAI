# openredirect-ai

Context-aware open redirect payload generation model. Fine-tuned Qwen2.5-1.5B that generates open redirect URL payloads for a given injection context.

## Results

| Metric | Rate | Target | Status |
|--------|------|--------|--------|
| T1 Synthetic (redirect fires) | 100.0% | 60% | ✅ |
| T2 Held-out filter combos | 30.0% | 30% | ✅ |
| Valid URL rate | 100.0% | 90% | ✅ |
| Diversity | 0.90 | 0.70 | ✅ |
| Refusal rate | 0% | ~0% | ✅ |

## Quickstart

```bash
python -m venv .venv-ml && source .venv-ml/Scripts/activate
pip install -e ".[dev]"
pip install torch==2.11.0+cu128 --index-url https://download.pytorch.org/whl/cu128
pip install transformers peft accelerate trl datasets

# Build dataset:
python scripts/02_build_pairs.py       # filter harness -> pairs_raw.jsonl
python scripts/03_validate_pairs.py    # oracle agreement gate (85%)
python scripts/04_finalize_splits.py   # split + quality gates -> train/val/test.jsonl

# Train:
python scripts/05_train.py             # LoRA on Qwen2.5-1.5B

# Evaluate:
python scripts/07_evaluate.py          # T1/T2/metrics

# Generate payloads:
python scripts/06_generate.py "URL taken from a redirect query parameter, blocks absolute URLs"
```

## Architecture

- **Context → payload** generation (same scaffold as xss-ai / ssrf-ai / etc.)
- **URL-parser oracle**: applies filters then checks if the URL would redirect
  to an external domain — pure Python, no callback listener needed
- **Filter harness**: 8 URL filters (block_absolute_url, require_same_domain,
  block_protocol_relative, block_at_symbol, block_backslash, url_decode,
  block_dotdot, allowlist_paths)
- **Training data**: 813 pairs from 21 contexts × 343 payloads
- **Model**: Qwen2.5-1.5B, bf16 LoRA (rank 32), 5 epochs

## Context taxonomy

Locations: `redirect_param`, `location_header`, `return_url`, `next_param`.

Filters model one server-side check each. Bypass strategies the model learns:
- `block_absolute_url` → protocol-relative (`//evil.com`) or scheme-without-slash (`https:evil.com`)
- `block_protocol_relative` → absolute URL
- `block_at_symbol` → `app.com.evil.com` host-confusion
- `url_decode` → encoded protocol-relative (`%2F%2Fevil.com%2F`)
- combined filters → chaining the above

## Layout

- `src/openredirect_ai/` — pipeline + ML modules
- `src/openredirect_ai/oracle/` — URL-parser oracle (check_fires)
- `src/openredirect_ai/eval/` — eval harness (T1/T2/metrics/report)
- `data/contexts/openredirect_contexts.yaml` — context taxonomy (21 contexts)
- `scripts/` — numbered pipeline entry points
