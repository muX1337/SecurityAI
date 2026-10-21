# xxe-ai

Context-aware XXE (XML External Entity) payload generation model. Fine-tuned Qwen2.5-1.5B that generates effective XXE payloads for a given XML injection context (location + server-side filters).

## Results

| Metric | Rate | Target | Status |
|--------|------|--------|--------|
| T1 Synthetic (structural fire) | 100.0% | 60% | ✅ |
| T2 Held-out filter combos | 100.0% | 30% | ✅ |
| Valid XML structure | 100.0% | 90% | ✅ |
| Diversity | 1.00 | 0.70 | ✅ |
| Refusal rate | 0% | ~0% | ✅ |

## Quickstart

```bash
python -m venv .venv && source .venv/Scripts/activate   # Windows
pip install -e ".[dev]"

# Build dataset:
python scripts/02_build_pairs.py       # filter harness -> pairs_raw.jsonl
python scripts/04_finalize_splits.py   # split + quality gates -> train/val/test.jsonl

# ML env (Python 3.12):
python3.12 -m venv .venv-ml && source .venv-ml/Scripts/activate
pip install torch==2.11.0+cu128 --index-url https://download.pytorch.org/whl/cu128
pip install transformers peft accelerate trl datasets httpx flask pydantic pyyaml
pip install -e ".[dev]"

# Train:
python scripts/05_train.py             # bf16 LoRA on Qwen2.5-1.5B

# Evaluate:
python scripts/07_evaluate.py          # T1/T2/metrics

# Generate payloads:
python scripts/06_generate.py "Input is placed inside an XML element body, file:// protocol blocked"
```

## Architecture

- **Context → payload** generation (same scaffold as ssrf-ai / xss-ai)
- **Prompt format**: `### Context:` / `### Payload:` with completion-only loss masking
- **Structural oracle**: Python stdlib XML parsers disable XXE by default, so the
  oracle checks payload *structure* — well-formedness + presence of an entity
  definition referencing external content (`SYSTEM`/`PUBLIC`) or a parameter-entity
  OOB pattern. A callback listener records OOB URL hits.
- **Filter harness**: 8 XML input filters (DOCTYPE/ENTITY/SYSTEM/parameter-entity
  blocking, file:// and http:// protocol blocking, comment stripping, DTD disable)
- **Context taxonomy**: 5 locations (xml_body, xml_attribute, xml_cdata, soap_body,
  svg_upload) × 8 filters = 22 training contexts
- **Training data**: 3,169 train / 410 val / 402 test pairs from 22 contexts × 6,043 payloads
- **Model**: Qwen2.5-1.5B, bf16 LoRA (rank 32, alpha 64), 5 epochs

## Training

| Epoch | Train Loss |
|-------|-----------|
| 0.5 | 1.151 |
| 1.0 | 0.471 |
| 1.5 | 0.385 |
| 2.0 | 0.324 |
| 2.5 | 0.306 |
| 3.0 | 0.287 |
| 3.5 | 0.279 |
| 4.0 | 0.268 |
| 4.5 | 0.262 |
| 5.0 | 0.257 |

- Final train loss: **0.381** (avg), final eval loss: **0.292**
- Trainable params: 36.9M / 1.58B (2.34%)
- Training time: **~2m26s** on NVIDIA GeForce RTX 5070

## Layout

- `src/xxe_ai/` — pipeline + ML modules
- `src/xxe_ai/context.py` — ContextSpec (location + filters), description rendering
- `src/xxe_ai/filters.py` — 8 XML input filters
- `src/xxe_ai/can_fire.py` — structural XXE effectiveness heuristic
- `src/xxe_ai/corpus_loader.py` — 6,043 built-in XXE payloads (generated variants)
- `src/xxe_ai/oracle/` — structural oracle (listener + check_fires)
- `src/xxe_ai/eval/` — eval harness (T1/T2/metrics/report)
- `scripts/` — 01–07 pipeline scripts
- `tests/` — 76 tests (context, filters, can_fire, oracle, harness, corpus, splits)
