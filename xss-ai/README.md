# xss-ai

Context-aware XSS payload generation model — **data pipeline** (v1, foundation).

See `docs/superpowers/specs/2026-07-07-xss-payload-generator-design.md` for the
full design.

## Quickstart

```bash
python -m venv .venv && source .venv/Scripts/activate
pip install -e ".[dev]"
playwright install chromium

# Build the dataset end-to-end:
python scripts/01_fetch_corpora.py     # clone SecLists + PayloadsAllTheThings
python scripts/02_build_pairs.py       # filter harness -> pairs_raw.jsonl
python scripts/03_validate_pairs.py    # browser oracle 85% gate
python scripts/04_finalize_splits.py   # split + quality gates -> train/val/test.jsonl
```

## Layout

- `src/xss_ai/` — pipeline modules (context, filters, can_fire, filter_harness, browser_oracle, splits).
- `data/contexts/contexts.yaml` — the context taxonomy (version-controlled).
- `data/pairs/` — generated datasets (gitignored, regenerable).
- `scripts/` — numbered pipeline entry points.
- `tests/` — unit + browser tests.

## Tests

```bash
pytest -v                 # all
pytest -v -m "not browser"  # skip slow browser tests
```

## Pipeline status

### v1 (foundation) — merged
Built the pipeline: ContextSpec schema, 15 filters, corpus loader, can-fire
heuristic, filter harness (Source 1), Playwright browser oracle (Source 2),
stratified splits, 5 quality gates.

### v1.5 (data expansion) — on `feat/data-expansion-v15`

Improvements over v1:
- **can_fire restricted to auto-firing event handlers** (onload/onerror/onfocus+
  autofocus/ontoggle+open). Interaction handlers (onmouseover/onclick/onfocusin)
  that never fire in a headless browser are now correctly rejected.
- **Taxonomy expanded** from 23 to 74 contexts across all 7 locations.
- **Splitting redesigned**: split-by-payload keeps all cross-context pairs (no
  data loss) and eliminates train/test leakage by construction.
- **Harness-level dedup** on (payload, context) removes near-duplicate variants.
- **Browser mining (Source 2b)** added: `scripts/06_mine_browser_pairs.py`.
- **Calibration script** added: `scripts/05_calibrate_can_fire.py`.

**Gate results after v1.5:**

| Gate | v1 | v1.5 |
|------|----|------|
| Balance (≤8%/context) | FAIL (7 over) | PASS |
| Dedup (no duplicate pairs) | FAIL (270) | PASS (0) |
| Leakage (train↔test) | FAIL (70) | PASS (0) |
| Contexts (≥30) | FAIL (11) | PASS (74) |
| Volume (≥10k train) | FAIL (1964) | FAIL (8235) |

4 of 5 gates now pass. The remaining volume gap (8235 < 10000) needs browser
mining or corpus expansion to close.

### Clean dataset (gold-standard) — on `feat/clean-dataset`

Resolves the ~20% agreement problem by browser-verifying every payload.

**Pipeline** (`scripts/07_build_clean_dataset.py`):
1. **Test-once**: browser-test each distinct filter-sim candidate payload in a
   plain `html_body` context. Of 2,001 candidates, **362 (18.1%) genuinely fire**.
2. **Expand**: re-pair the 362 verified payloads across all 74 contexts where
   they survive the reflection pipeline → **5,251 gold-standard pairs**.
3. **Split**: payload-based split → **4207 train / 479 val / 565 test**.

Every pair has `verified_by: "playwright"` — 100% browser-confirmed execution.

| Metric | Value |
|--------|-------|
| Distinct payloads browser-tested | 2,001 |
| Payloads confirmed firing | 362 (18.1%) |
| Gold-standard pairs (after expansion) | 5,251 |
| Split | 4207 / 479 / 565 (train/val/test) |
| Contexts represented | 74 |
| Browser verification | 100% (`verified_by=playwright`) |

The ~18% agreement rate confirms the earlier finding: ~82% of the raw corpus's
"XSS payloads" don't actually execute in a modern Chromium. The clean dataset
filters to only the 18% that do, expanded across diverse filtered contexts.

**Reproducibility:** the browser-test phase takes ~50 min and checkpoints to
`data/pairs/verified_payloads.jsonl` every 50 payloads. Resume with
`python scripts/07_build_clean_dataset.py --resume`.

## Model (v1)

Fine-tuned Qwen2.5-1.5B via LoRA on the browser-verified clean dataset.

### Training
- Base: Qwen/Qwen2.5-1.5B
- Method: bf16 LoRA (rank 16, alpha 32, 7 target modules) — 4-bit QLoRA unavailable on Windows (no bitsandbytes)
- Data: 4207 train / 479 val pairs (100% browser-verified)
- Hyperparams: 3 epochs, LR 2e-4, cosine, batch 32 (eff), seq 256, bf16
- Training time: 9.5 min on RTX 5070 (12 GB)
- Final train loss: 0.41, eval loss: 1.38

### Results
- **Browser execution success: ~27%** (4/15 val contexts, greedy decode)
- The model generates real XSS payloads (CSS-animation-based `onanimationend`, `onerror`, `onload` variants, data-URI scripts)
- Strengths: fires reliably on contexts where brackets survive (plain HTML body, block-script, lowercase)
- Weaknesses: misses on heavily-filtered contexts (strip `<>`, escape `<>`, URL params) — the dominant greedy payload uses `<style>` tags that get stripped
- Sampling (temperature 0.7, best-of-3) shows more context-variety than greedy but similar hit rate

### Usage
```python
from xss_ai.generate import load_model, generate
model, tok = load_model("models/xss-qwen1.5b-v1/merged")
payloads = generate(model, tok, "Input reflected into HTML body, < and > stripped.",
                    strategy="sampling", n=5)
```

### Known limitations (v1)
- **Low context-sensitivity under greedy decoding** — the model has a dominant go-to payload (`@keyframes` + `onanimationend`) that it outputs regardless of context. Sampling produces more variety.
- The model has NOT been safety-aligned in any way — it generates XSS payloads on request. Use only for authorized security testing.

### Files
- `models/xss-qwen1.5b-v1/checkpoint-{65,130,195,260,325,390,396}/` — training checkpoints
- `models/xss-qwen1.5b-v1/final/` — final epoch LoRA adapter
- `models/xss-qwen1.5b-v1/merged/` — standalone merged model (no adapter needed)

## Evaluation Harness

3-tier browser-execution evaluation (`scripts/10_evaluate.py`).

### Architecture
- **T1 (Synthetic):** model generates payloads for held-out test-split contexts; `BatchedOracle` (persistent Chromium) checks `alert()` fires.
- **T2 (Held-out combos):** generates filter combinations NOT in training; verifies solvability; tests model generalization.
- **Secondary metrics:** syntax validity, diversity (unique/10 samples), refusal rate.
- **Report:** JSON + markdown with per-context breakdown and failure log.

### v1 Eval Results (80 T1 pairs, `reports/2026-07-14-v1/`)

| Tier | Rate | Target | Status |
|------|------|--------|--------|
| T1 Synthetic | 56% | 60% | ❌ FAIL |
| T2 Held-out | 0% | 30% | ❌ FAIL |
| Valid Syntax | 100% | 90% | ✅ PASS |
| Diversity | 0.89 | 0.70 | ✅ PASS |
| Refusal Rate | 0% | ~0% | ✅ |

**Key diagnostic from failure log:** The model outputs the same `@keyframes`+`onanimationend` payload for every context. It fires at 100% on contexts where brackets survive (plain body, keyword filters, parens/backslash stripping) but 0% on contexts requiring bracket-escaping (`escape_angle_brackets_html`, `strip_angle_brackets`), attribute breakout (`attr_dq`), or URL injection (`url_param`).

**Improvement path:** context-conditional training (penalize same-payload-different-context), more training data for hard-filter contexts, or larger base model (3B/7B).
