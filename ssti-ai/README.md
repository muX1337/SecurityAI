# ssti-ai

Context-aware SSTI (Server-Side Template Injection) payload generation model. Fine-tuned
Qwen2.5-1.5B that generates template payloads for a given injection context (template engine
+ input filters).

## Results

| Metric | Rate | Target | Status |
|--------|------|--------|--------|
| T1 Synthetic (eval success) | 100.0% | 60% | PASS |
| T2 Held-out filter combos | 20.0% | 30% | marginal |
| Valid template-expr rate | 100.0% | 90% | PASS |
| Diversity | 0.60 | 0.70 | marginal |
| Refusal rate | 0% | ~0% | PASS |

T1 (in-distribution evaluation success) far exceeds target. T2/Diversity are honest v1
limits of the 210-pair training set: the model overfits to high-confidence math probes and
does not always switch syntax when an engine's primary delimiter is blocked. Both improve
with more training pairs (deferred to v2).

## Quickstart

```bash
# Core pipeline (Python 3.14):
python -m venv .venv && source .venv/Scripts/activate
pip install -e ".[dev]"

# Build dataset:
python scripts/02_build_pairs.py       # filter harness + oracle -> pairs_raw.jsonl
python scripts/03_validate_pairs.py    # 85% filter-sim/oracle agreement gate
python scripts/04_finalize_splits.py   # split + quality gates -> train/val/test.jsonl

# ML env (Python 3.12):
py -3.12 -m venv .venv-ml && source .venv-ml/Scripts/activate
pip install torch==2.11.0+cu128 --index-url https://download.pytorch.org/whl/cu128
pip install -e ".[dev]"
pip install transformers peft accelerate trl datasets httpx flask

# Train:
python scripts/05_train.py             # bf16 LoRA on Qwen2.5-1.5B

# Evaluate:
python scripts/07_evaluate.py          # T1/T2/metrics

# Generate payloads:
python scripts/06_generate.py "User input is rendered inside a Jinja2 template body (Flask). No input filtering is applied."
```

## Architecture

- **Context → payload** generation (same scaffold as xss-ai / ssrf-ai — 7th vuln-type AI)
- **Simulated template-renderer oracle**: pure-Python, dependency-free — checks whether the
  target engine would evaluate the surviving expression (math result changes, or a data/RCE
  marker is intact inside expression delimiters). No browser, no HTTP listener.
- **Filter harness**: 8 input filters (delimiter/keyword blocking) × 5 template engines
- **Training data**: 269 oracle-verified pairs (210 train / 21 val / 38 test) from
  22 contexts × 54 payloads; 100% filter-sim/oracle agreement
- **Model**: Qwen2.5-1.5B, bf16 LoRA (rank 32), 5 epochs, train_loss 0.87, 64s on RTX 5070

## Layout

- `src/ssti_ai/` — pipeline + ML modules
- `src/ssti_ai/oracle/check_fires.py` — simulated template-renderer oracle
- `src/ssti_ai/eval/` — eval harness (T1/T2/metrics/report)
- `data/contexts/ssti_contexts.yaml` — context taxonomy (22 contexts)
- `scripts/` — numbered pipeline entry points
- `docs/superpowers/specs/` — design spec
