# crlf-ai

Context-aware CRLF / HTTP response injection payload generation model. A fine-tuned
Qwen2.5-1.5B that generates CRLF injection payloads (response splitting, header
injection, body injection) for a given injection context (location + server-side
input filters).

## Results (eval-v1)

| Metric | Rate | Target | Status |
|--------|------|--------|--------|
| T1 Synthetic (oracle fire rate) | 100.0% | 60% | PASS |
| T2 Held-out filter combos | 20.0% | 30% | FAIL |
| Valid Header rate | 100.0% | 90% | PASS |
| Diversity | 0.60 | 0.70 | FAIL |
| Refusal rate | 0.0% | ~0% | PASS |

T1 hits a perfect 100% across all 12 test contexts — the model reliably generates
working payloads for every context distribution it was trained on. T2 and diversity
fall short of target, the expected v1 profile given the small corpus: the quality
gates flagged the dataset as undersized (213 train pairs vs the 500 minimum, several
plain/decode contexts at 8.5-8.9% vs the 8% balance cap). The generated payloads are
syntactically valid header injections 100% of the time; the T2 failures are all on
hardened held-out *combinations* of block filters where the trained payload gets
filtered out and the model has not yet learned the exotic bypasses (single-byte,
double-encoding, unicode-overlong) for novel filter stacks.

## Quickstart

```bash
python -m venv .venv-ml && source .venv-ml/Scripts/activate
pip install -e ".[dev]"
pip install torch transformers peft accelerate trl datasets httpx flask
# For CUDA: pip install torch==2.11.0+cu128 --index-url https://download.pytorch.org/whl/cu128

# Tests (no GPU needed):
source .venv/Scripts/activate
pytest tests/ -v

# Build dataset:
python scripts/02_build_pairs.py       # filter harness -> pairs_raw.jsonl
python scripts/04_finalize_splits.py   # dedup + split + quality gates -> train/val/test.jsonl

# Train:
python scripts/05_train.py             # LoRA on Qwen2.5-1.5B

# Evaluate:
python scripts/07_evaluate.py          # T1/T2/metrics

# Generate payloads:
python scripts/06_generate.py "User input is reflected into a Set-Cookie header; URL decoding is applied."
python scripts/06_generate.py --context-id crlf-set-cookie-url-decode -n 5
python scripts/06_generate.py --list-contexts
```

## Architecture

- **Context -> payload** generation. Each context is a (location, filters) pair.
- **CRLF oracle**: pure-Python HTTP response construction simulator. No network
  listener — it builds a simulated response with the payload injected into the
  header slot, then parses the header block (lenient newline splitting) and checks
  whether the injection introduced extra header lines or injection keywords.
  Deterministic and fast (21 T1 pairs in ~5s).
- **Filter harness**: 8 input filters in two kinds — decode filters (`url_decode`,
  `double_decode`, which run first) and block filters (`block_crlf`,
  `block_cr_only`, `block_lf_only`, `block_percent_0d`, `block_percent_0a`,
  `block_header_keywords`). Models the classic decode-then-sanitize server.
- **Context taxonomy**: 20 contexts in `data/contexts/crlf_contexts.yaml` covering
  4 reflection locations x plain / decode / block / combined filters.
- **Training data**: 265 pairs from 20 contexts x 29 payloads (built-in corpus),
  deduped on (normalized payload, context id), split 80/10/10 by payload so there
  is zero train/test leakage by construction.
- **Model**: Qwen2.5-1.5B, bf16 LoRA (rank 32, alpha 64) on all linear projections,
  5 epochs, completion-only loss masking. 36.9M trainable params (2.34%).

## Pipeline

```
contexts.yaml  +  corpus  --02_build_pairs-->  pairs_raw.jsonl
                                                    |
                          04_finalize_splits -------+----> train/val/test.jsonl + gates
                                                    |
                          05_train -----------------+----> models/crlf-qwen1.5b-v1/final
                                                    |
                          07_evaluate --------------+----> reports/eval-v1/
```

## Layout

- `src/crlf_ai/` - pipeline + ML modules
- `src/crlf_ai/oracle/` - CRLF oracle (HTTP response construction simulator)
- `src/crlf_ai/eval/` - eval harness (T1/T2/secondary metrics + report)
- `data/contexts/crlf_contexts.yaml` - context taxonomy (20 contexts)
- `scripts/` - numbered pipeline entry points
- `tests/` - unit tests for every module
