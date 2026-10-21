# Model Management Guide

How to retrain models, swap base models, evaluate performance, and troubleshoot.

## Understanding the training pipeline

Every vulnerability model follows the same pipeline:

```
Built-in corpus → filter harness → (context, payload) pairs → train/val/test split
                                                                             ↓
Browser/oracle verification ← 10% sample validation (85% gate)
                                                                             ↓
QLoRA fine-tune → evaluate → production model
```

### Pipeline scripts (per project)

| Script | Purpose | Venv |
|--------|---------|------|
| `01_fetch_corpora.py` | Download external payload lists (optional) | `.venv` |
| `02_build_pairs.py` | Generate (context, payload) training pairs | `.venv` |
| `03_validate_pairs.py` | Oracle-validate 10% sample (85% gate) | `.venv` |
| `04_finalize_splits.py` | Split into train/val/test + quality gates | `.venv` |
| `05_train.py` | Fine-tune the model | `.venv-ml` |
| `06_generate.py` | CLI for generating payloads | `.venv-ml` |
| `07_evaluate.py` | Run T1/T2 evaluation | `.venv-ml` |

## Retraining a model

### When to retrain

- You added new training data (new payloads, new contexts)
- You want to try a different base model
- The model is underperforming on specific contexts

### Steps

```bash
cd SecurityAI/ssrf-ai  # or whichever project

# 1. (Optional) Modify training data
#    Edit: data/contexts/contexts.yaml (add/modify contexts)
#    Edit: src/<pkg>/corpus_loader.py (add payloads to BUILTIN_PAYLOADS)

# 2. Rebuild training pairs
source .venv/Scripts/activate
python scripts/02_build_pairs.py
python scripts/04_finalize_splits.py

# 3. Check quality gates (should say "GATES PASS")
# If gates fail, add more payloads or contexts

# 4. Retrain
source .venv-ml/Scripts/activate
rm -rf models/<model-name>/  # remove old model
python scripts/05_train.py

# 5. Evaluate
python scripts/07_evaluate.py

# 6. If score improved → new model is in models/<name>/final/
```

### Training time estimates

| Model Size | Dataset Size | Training Time (RTX 5070) |
|-----------|-------------|-------------------------|
| 1.5B | ~5k pairs | ~8 min |
| 3B | ~5k pairs | ~12 min |
| 4B | ~5k pairs | ~22 min (clean GPU) |

## Batch retraining (retrain-all)

Retrains **all (or selected) agents on a new base model** in one go —
for when a new model generation drops. Runs sequentially (single GPU);
a full batch of 9 agents takes a day+.

```bash
cd SecurityAI/exploitgym

# plan only — show what would run, no training
.venv/Scripts/python scripts/retrain_all.py --base-model Qwen/Qwen3-4B --dry-run

# retrain everything on the new base
.venv/Scripts/python scripts/retrain_all.py --base-model Qwen/Qwen3-4B

# just two agents
.venv/Scripts/python scripts/retrain_all.py --base-model Qwen/Qwen3-4B --agents xss,ssrf
```

How it works:

- Versions are named automatically after the model family —
  `Qwen/Qwen3-4B` → `ssrf-qwen3-4b-v1`, next free number per agent
  (`xss-qwen3-4b-v3` if v1/v2 exist). Old models are never overwritten.
- Each project's train script reads `BASE_MODEL_ID` and `RETRAIN_VERSION`
  from the environment (the batch runner sets both).
- A failure in one agent doesn't stop the batch; a summary is posted to
  the message board.
- The dashboard offers the same thing (Models tab → "Retrain all agents",
  base-model picker with live progress).

Notes:
- Cloud models (GLM-5.3) **cannot** be fine-tuning bases — pick a locally
  downloadable HF checkpoint that fits in VRAM (see the table above).
- After a batch, evaluate each new model and activate it via the
  dashboard Models tab or `config.py`'s `model_path`.

## Changing the base model

### Supported base models

| Model | VRAM (bf16 LoRA) | Fits 12GB? | Notes |
|-------|-------------------|------------|-------|
| Qwen2.5-1.5B | ~6GB | ✅ | Best speed/quality balance |
| Qwen2.5-3B | ~8GB | ✅ | No improvement over 1.5B (tested) |
| Qwen3-4B | ~10GB | ✅ (tight) | Same performance as 1.5B (tested) |
| Qwen2.5-7B | ~14GB | ❌ | Needs QLoRA + Linux |
| Qwen2.5-14B | ~28GB | ❌ | Inference only via Ollama |

### How to swap

Edit `src/<package>/train.py`:

```python
# Change this line:
MODEL_ID = "Qwen/Qwen2.5-1.5B"
# To:
MODEL_ID = "Qwen/Qwen3-4B"  # or any supported model
```

Then retrain:
```bash
source .venv-ml/Scripts/activate
python scripts/05_train.py
```

### Important: Also update generate.py

The `generate.py` imports `MODEL_ID` from `train.py`, so it updates automatically. But if you use a different model at inference than training, update `src/<package>/generate.py` directly.

### Batch size adjustments

If you get CUDA out-of-memory errors:

```python
# In TrainConfig:
batch_size=4,           # reduce from 8 to 4
grad_accum_steps=8,      # increase from 4 to 8 (keeps effective batch = 32)
```

## Evaluating model performance

### Quick evaluation (30 samples, ~3 min)

```bash
source .venv-ml/Scripts/activate
python scripts/07_evaluate.py --max-t1 30
```

### Full evaluation (all test pairs, ~45 min)

```bash
python scripts/07_evaluate.py --max-t1 0
```

### Understanding scores

| Metric | Target | Meaning |
|--------|--------|---------|
| T1 Synthetic | ≥60% | Payloads fire in the oracle |
| T2 Held-out | ≥30% | Generalizes to unseen filter combos |
| Valid syntax | ≥90% | Outputs are well-formed |
| Diversity | ≥0.7 | Generates varied payloads |
| Refusal rate | ~0% | Model doesn't refuse to generate |

### Interpreting T1 score

The T1 score has a **binary pattern** — the model either scores 100% or 0% on each context type:

```
100% ← contexts where the model's technique works
  0% ← contexts where the model doesn't know the technique
```

Overall T1 = (number of "easy" contexts) / (total contexts)

To improve: identify the 0% contexts and add targeted training data for them.

## Improving a weak model

### Step 1: Identify failing contexts

```bash
python scripts/07_evaluate.py --max-t1 30
# Check the per-context breakdown in the report
# Contexts scoring 0% are the ones to fix
```

### Step 2: Generate targeted training data

Write a script that generates payloads specifically for the failing contexts. See `xss-ai/scripts/generate_targeted_data.py` for an example.

Key principles:
- Only include payloads that **actually fire** in the oracle
- Test against the specific failing context types
- 50-100 targeted payloads is usually enough

### Step 3: Merge with existing training data

```python
# Load original training data
original = Path('data/pairs/clean/train.jsonl').read_text().splitlines()

# Load targeted fix data
fix = Path('data/pairs/targeted_fix.jsonl').read_text().splitlines()

# Duplicate fix data 3x for weight (teaching signal boost)
boosted = fix * 3

# Merge (targeted data should be 5-10% of total)
merged = original + boosted
Path('data/pairs/clean/train.jsonl').write_text('\n'.join(merged) + '\n')
```

### Step 4: Retrain and evaluate

```bash
python scripts/05_train.py
python scripts/07_evaluate.py --max-t1 0  # full test for accurate comparison
```

## Model file structure

```
models/
├── <model-name>/
│   ├── checkpoint-XXX/          # Training checkpoints (can delete)
│   ├── checkpoint-YYY/
│   └── final/                   # ← THE production model
│       ├── adapter_config.json  # LoRA configuration
│       ├── adapter_model.safetensors  # Trained weights
│       ├── tokenizer.json
│       └── tokenizer_config.json
```

The `final/` directory is what you point to for inference.

## Swapping models in ExploitGym

Edit `exploitgym/src/exploitgym/config.py`:

```python
AgentConfig(
    name="xss_agent",
    vuln_type="xss",
    package="xss_ai",
    project_root=PLAYGROUND / "xss-ai",
    model_path="models/xss-qwen1.5b-v4/final",  # ← Change this
    contexts_yaml="data/contexts/contexts.yaml",
    venv_ml=".venv-ml",
),
```

## Troubleshooting

### Model won't load
```bash
# Check CUDA is available
python -c "import torch; print(torch.cuda.is_available())"

# If False, reinstall torch with CUDA:
pip install torch==2.11.0+cu128 --index-url https://download.pytorch.org/whl/cu128
```

### Out of memory during training
```bash
# Close GPU-using apps, then reduce batch size
# In train.py: batch_size=4, grad_accum_steps=8
```

### Model generates garbage
```bash
# Check if MODEL_ID in train.py matches the trained model
grep MODEL_ID src/*/train.py
# If you trained with 1.5B but MODEL_ID says 4B, you'll get size mismatch
```

### Evaluation scores 0%
```bash
# The model might not have learned any technique
# Check training data volume:
wc -l data/pairs/clean/train.jsonl
# Need at least 500 pairs
```
