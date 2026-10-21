# pathtraversal-ai

Context-aware path traversal / LFI payload generation model. Fine-tuned Qwen2.5-1.5B (LoRA).

## Results

| Metric | Rate | Target | Status |
|--------|------|--------|--------|
| T1 Synthetic (file marker read) | 79.3% | 60% | ✅ |
| T2 Held-out filter combos | 30.0% | 30% | ✅ |
| Valid path rate | 100.0% | 90% | ✅ |
| Diversity | 0.80 | 0.70 | ✅ |
| Refusal rate | 0.0% | ~0% | ✅ |

All five evaluation gates pass.

## Quickstart

```bash
# Dev/test environment (Python 3.14)
python -m venv .venv && source .venv/Scripts/activate   # Windows: .venv/Scripts/activate
pip install -e ".[dev]"

# ML environment (Python 3.12, CUDA)
py -3.12 -m venv .venv-ml && source .venv-ml/Scripts/activate
pip install torch==2.11.0+cu128 --index-url https://download.pytorch.org/whl/cu128
pip install transformers peft accelerate trl datasets httpx flask
pip install -e .

# Data pipeline + train + eval
python scripts/02_build_pairs.py
python scripts/04_finalize_splits.py
python scripts/05_train.py
python scripts/07_evaluate.py

# Generate payloads interactively
python scripts/06_generate.py "Input passed to file_get_contents, ../ stripped non-recursively"
python scripts/06_generate.py --list-contexts
```

## Architecture

- **Oracle**: self-contained file-system oracle (pure Python stdlib — no subprocess,
  no network). Creates a temp sandbox `<tmpdir>/base/` with a legitimate file, and
  plants marker files (`secret.txt`, `etc/passwd`, `Windows/win.ini`, ...) at every
  ancestor directory level. The vulnerable code simulates
  `open(base_dir + "/" + filtered_payload)`, resolves the path via `os.path.normpath`
  (so `../` escapes base), and reads it. If `PATH_TRAVERSAL_MARKER` appears → fire.
  The server URL-decodes raw input once before filters (mirrors real web servers).
  PHP/stream wrappers (`php://`, `file://`, `data://`) count as primitive-level fires.
- **Filters**: 8 path traversal filters (strip_dotdot, strip_dotdot_recursive,
  basename_only, block_absolute, block_null_byte, url_decode, double_decode,
  prefix_append)
- **Contexts**: 21 injection points across 4 locations (file_include, file_read,
  download_param, template_path)
- **Training data**: 837 pairs from 21 contexts × 59 payloads (673 train / 82 val / 82 test)
- **Training**: Qwen2.5-1.5B LoRA (r=32, α=64), 5 epochs, final train_loss=0.338,
  eval_loss=1.459, ~225s on RTX 5070

## Project structure

```
src/pathtraversal_ai/
  context.py        # ContextSpec, LOCATIONS, filter prose
  filters.py        # 8 filter registry
  can_fire.py       # static traversal heuristic
  oracle/           # file-system marker oracle
  corpus_loader.py  # built-in + external payloads
  filter_harness.py # generate (context, payload) pairs
  splits.py         # stratified split + quality gates
  prompt.py         # ### Context / ### Payload format
  train.py          # LoRA training (Qwen2.5-1.5B)
  dataset.py        # completion-only loss masking
  generate.py       # inference
  eval/             # T1/T2 harness + report
```

## Context taxonomy

**Locations** (where the path is injected):
- `file_include` — path passed to include/require (PHP-style)
- `file_read` — path passed to fopen/file_get_contents/readFile
- `download_param` — path in a download endpoint (?file=INPUT)
- `template_path` — path in a template loader

**Filters**:
- `strip_dotdot` — removes `../` sequences (single non-recursive pass)
- `strip_dotdot_recursive` — repeatedly removes `../` until none left
- `basename_only` — applies basename() (strips all directory components)
- `block_absolute` — blocks paths starting with `/` or drive letters (`C:\`)
- `block_null_byte` — blocks `%00` null byte injection
- `url_decode` — URL-decodes input once before filtering
- `double_decode` — URL-decodes twice (catches double-encoding)
- `prefix_append` — prepends a base directory before file open
