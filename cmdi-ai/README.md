# cmdi-ai

Context-aware command injection payload generation model. Fine-tuned Qwen2.5-1.5B (LoRA).

## Results

| Metric | Rate | Target | Status |
|--------|------|--------|--------|
| T1 Synthetic (marker file created) | 100.0% | 60% | ✅ |
| T2 Held-out filter combos | 90.0% | 30% | ✅ |
| Valid command rate | 100.0% | 90% | ✅ |
| Diversity | 1.00 | 0.70 | ✅ |
| Refusal rate | 0.0% | ~0% | ✅ |

## Quickstart

```bash
python -m venv .venv-ml && source .venv-ml/Scripts/activate
pip install -e ".[dev]"
pip install torch==2.11.0+cu128 --index-url https://download.pytorch.org/whl/cu128
pip install transformers peft accelerate

python scripts/02_build_pairs.py
python scripts/04_finalize_splits.py
python scripts/05_train.py
python scripts/07_evaluate.py
python scripts/06_generate.py "Input is passed as an argument to a shell command, semicolons blocked"
```

## Architecture

- **Oracle**: subprocess-based (bash). Runs the payload injected into a vulnerable
  command via `bash -c` and checks if a marker file was created. Detection by
  transforming the payload's injection vector (`;`, `|`, `&&`, `&`, `` ` ``, `$()`)
  into a marker-write (`echo MARKER > path`). Conditional operators (`&&`/`||`)
  use `true`/`false` base commands so short-circuit semantics are respected.
- **Filters**: 8 CMDi filters (block semicolon, pipe, ampersand, backtick, dollar,
  redirect, keywords, alphanumeric-only)
- **Contexts**: 24 injection points across 4 locations (shell_arg, shell_command,
  filename_arg, variable_value)
- **Training data**: 3223 pairs from 24 contexts × 236 payloads (2609 train / 304 val / 310 test)
- **Training**: Qwen2.5-1.5B LoRA (r=32), 5 epochs, final train_loss=1.125, eval_loss=1.902

## Project structure

```
src/cmdi_ai/
  context.py        # ContextSpec, LOCATIONS, filter prose
  filters.py        # 8 filter registry
  can_fire.py       # static metachar heuristic
  oracle/           # subprocess-based marker oracle
  corpus_loader.py  # built-in + external payloads
  filter_harness.py # generate (context, payload) pairs
  splits.py         # stratified split + quality gates
  prompt.py         # ### Context / ### Payload format
  train.py          # LoRA training (Qwen2.5-1.5B)
  dataset.py        # completion-only loss masking
  generate.py       # inference
  eval/             # T1/T2 harness + report
```
