# sqli-ai

Context-aware SQL injection payload generation model. Fine-tuned Qwen2.5-1.5B.

## Results

| Metric | Rate | Target | Status |
|--------|------|--------|--------|
| T1 Synthetic (data extraction) | 71.4% | 60% | ✅ |
| T2 Held-out filter combos | 10.0% | 30% | ❌ |
| Valid SQL rate | 100% | 90% | ✅ |
| Diversity | 0.70 | 0.70 | ✅ |
| Refusal rate | 0% | ~0% | ✅ |

## Quickstart

```bash
python -m venv .venv-ml && source .venv-ml/Scripts/activate
pip install -e ".[dev]"
pip install torch==2.11.0+cu128 --index-url https://download.pytorch.org/whl/cu128
pip install transformers peft accelerate trl datasets httpx flask

python scripts/02_build_pairs.py
python scripts/04_finalize_splits.py
python scripts/05_train.py
python scripts/07_evaluate.py
python scripts/06_generate.py "Input injected into SQL string literal, single quotes escaped"
```

## Architecture

- **Oracle**: in-memory SQLite database (no external deps). UNION extraction, error-based, boolean-based detection.
- **Filters**: 9 SQL filters (quote escaping, keyword blocking, comment blocking, numeric cast)
- **Contexts**: 20 injection points across 5 locations (string literal, numeric, ORDER BY, column, INSERT)
- **Training data**: 923 pairs from 20 contexts × 67 payloads
