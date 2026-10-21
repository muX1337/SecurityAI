# Adding a New Vulnerability Type

How to create a new vulnerability model using the proven scaffold.

## Overview

Every vulnerability model in SecurityAI shares the same architecture:
1. **Context taxonomy** — where input enters, what filters are applied
2. **Filter simulation** — Python functions modeling server-side defenses
3. **Oracle** — ground-truth verification that a payload "works"
4. **Corpus** — known payloads
5. **Training pipeline** — the same QLoRA fine-tuning

The only things you design for a new vuln type are: **contexts, filters, and the oracle**.

## Step-by-step: Adding a new vulnerability

### Step 1: Create the project

```bash
cd SecurityAI
mkdir <vuln>-ai
cd <vuln>-ai
git init

mkdir -p src/<vuln>_ai data/contexts scripts tests docs/superpowers/specs
```

### Step 2: Create pyproject.toml

```toml
[project]
name = "<vuln>-ai"
version = "0.1.0"
requires-python = ">=3.11"
dependencies = ["pydantic>=2.6,<3", "pyyaml>=6.0,<7"]

[project.optional-dependencies]
dev = ["pytest>=8.0,<9"]

[build-system]
requires = ["setuptools>=68"]
build-backend = "setuptools.build_meta"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
testpaths = ["tests"]
addopts = "-q"
```

### Step 3: Copy generic modules from SSRF project

```bash
cp ../ssrf-ai/src/ssrf_ai/prompt.py src/<vuln>_ai/
cp ../ssrf-ai/src/ssrf_ai/pair_schema.py src/<vuln>_ai/
cp ../ssrf-ai/src/ssrf_ai/splits.py src/<vuln>_ai/
```

These are identical across all projects — no modifications needed.

### Step 4: Define the context taxonomy

Create `src/<vuln>_ai/context.py`:

```python
"""ContextSpec: the structured description of a <vuln> injection point."""
from __future__ import annotations
from pydantic import BaseModel, Field

LOCATIONS: tuple[str, ...] = (
    # Define where input enters for this vulnerability
    "location_1",
    "location_2",
)

_LOCATION_PROSE: dict[str, str] = {
    "location_1": "Description of injection location 1.",
    "location_2": "Description of injection location 2.",
}

_FILTER_PROSE: dict[str, str] = {
    "filter_1": "Description of what filter 1 blocks.",
    "filter_2": "Description of what filter 2 blocks.",
}

class ContextSpec(BaseModel):
    id: str
    location: str
    filters: list[str] = Field(default_factory=list)
    description: str | None = None

    def model_post_init(self, __context) -> None:
        if self.location not in LOCATIONS:
            raise ValueError(f"unknown location {self.location!r}")
        unknown = [f for f in self.filters if f not in _FILTER_PROSE]
        if unknown:
            raise ValueError(f"unknown filter(s): {unknown}")

def render_description(ctx: ContextSpec) -> str:
    if ctx.description is not None:
        return ctx.description
    parts = [_LOCATION_PROSE[ctx.location]]
    for f in ctx.filters:
        parts.append(_FILTER_PROSE.get(f, f"Filter applied: {f}."))
    return " ".join(parts)

def simulate_reflection(ctx: ContextSpec, payload: str) -> str:
    from .filters import apply_filters
    return apply_filters(payload, ctx.filters)
```

### Step 5: Define the filters

Create `src/<vuln>_ai/filters.py`:

```python
"""Filter registry for <vuln>."""
from __future__ import annotations
from collections.abc import Callable

FILTERS: dict[str, Callable[[str], str]] = {}

def register(name: str):
    def deco(fn):
        FILTERS[name] = fn
        return fn
    return deco

def get_filter(name: str):
    if name not in FILTERS:
        raise KeyError(f"unknown filter {name!r}")
    return FILTERS[name]

def apply_filters(payload: str, filter_names: list[str]) -> str:
    out = payload
    for name in filter_names:
        out = get_filter(name)(out)
        if out == "":
            return ""
    return out

@register("filter_1")
def filter_1(s: str) -> str:
    # Return "" to block, or the string to pass
    return "" if "blocked_pattern" in s else s

@register("filter_2")
def filter_2(s: str) -> str:
    return s.replace("dangerous", "")
```

### Step 6: Build the oracle

This is the most important part — **the oracle determines what "success" means**.

Create `src/<vuln>_ai/oracle/check_fires.py`:

```python
"""Oracle: check_fires(ctx, payload) -> bool.

The oracle defines ground truth for whether a payload 'works'.
"""
from __future__ import annotations
from ..context import ContextSpec, simulate_reflection
from ..can_fire import can_fire

def check_fires(ctx: ContextSpec, payload: str) -> bool:
    """Return True if the payload successfully exploits this context."""
    # 1. Apply the server's filters
    filtered = simulate_reflection(ctx, payload)
    if not filtered:
        return False  # blocked

    # 2. Check if the payload achieves its goal
    # This is vuln-type specific:
    # - XSS: does alert() fire in a browser?
    # - SQLi: does the query return different results?
    # - SSRF: does the server make a request to our listener?
    # - Your vuln: define what "success" looks like

    # Example for a simple check:
    return "success_indicator" in filtered

class OracleSession:
    """Batch checking (reuses resources across calls)."""
    def __enter__(self):
        return self
    def __exit__(self, *args):
        return False
    def check_fires(self, ctx, payload):
        return check_fires(ctx, payload)
```

### Step 7: Create the corpus

Create `src/<vuln>_ai/corpus_loader.py` with built-in payloads:

```python
BUILTIN_PAYLOADS = [
    # List 30-60 known payloads for this vulnerability
    "payload_1",
    "payload_2",
    # ...
]
```

### Step 8: Create the filter harness

Copy from SSRF project and update imports:

```bash
cp ../ssrf-ai/src/ssrf_ai/filter_harness.py src/<vuln>_ai/
cp ../ssrf-ai/src/ssrf_ai/can_fire.py src/<vuln>_ai/
# Then update all imports from ssrf_ai to <vuln>_ai
sed -i 's/ssrf_ai/<vuln>_ai/g' src/<vuln>_ai/filter_harness.py
```

### Step 9: Create the context YAML

Create `data/contexts/<vuln>_contexts.yaml`:

```yaml
contexts:
  - id: <vuln>-location1-plain
    location: location_1
    filters: []
  - id: <vuln>-location1-filter1
    location: location_1
    filters: [filter_1]
  # ... 15-25 contexts covering all location × filter combinations
```

### Step 10: Write pipeline scripts

Copy from SSRF and update:

```bash
for script in 01_fetch_corpora.py 02_build_pairs.py 03_validate_pairs.py 04_finalize_splits.py; do
    cp ../ssrf-ai/scripts/$script scripts/
    sed -i 's/ssrf_ai/<vuln>_ai/g; s/ssrf-qwen/<vuln>-qwen/g' scripts/$script
done
```

### Step 11: Set up venvs and run the pipeline

```bash
# Data pipeline venv
python -m venv .venv
source .venv/Scripts/activate
pip install -e ".[dev]"

# Run pipeline
python scripts/02_build_pairs.py
python scripts/04_finalize_splits.py
# Check: "GATES PASS"

# Run tests
pytest tests/ -v
```

### Step 12: Add ML training modules

```bash
# ML venv
py -3.12 -m venv .venv-ml
source .venv-ml/Scripts/activate
pip install -e ".[dev]"
pip install torch==2.11.0+cu128 --index-url https://download.pytorch.org/whl/cu128
pip install transformers peft accelerate trl datasets httpx flask

# Copy training modules from SSRF
for mod in dataset.py train.py generate.py; do
    cp ../ssrf-ai/src/ssrf_ai/$mod src/<vuln>_ai/
    sed -i 's/ssrf_ai/<vuln>_ai/g; s/SSRFDataset/<VULN>Dataset/g; s/ssrf-qwen1.5b-v1/<vuln>-qwen1.5b-v1/g' src/<vuln>_ai/$mod
done

# Train
python scripts/05_train.py

# Create generate CLI
cp ../ssrf-ai/scripts/06_generate.py scripts/
sed -i 's/ssrf_ai/<vuln>_ai/g; s/ssrf-gen/<vuln>-gen/g; s/ssrf_contexts/<vuln>_contexts/g' scripts/06_generate.py

# Evaluate
# Copy eval harness from SSRF
mkdir -p src/<vuln>_ai/eval
cp ../ssrf-ai/src/ssrf_ai/eval/harness.py src/<vuln>_ai/eval/
cp ../ssrf-ai/src/ssrf_ai/eval/report.py src/<vuln>_ai/eval/
# Update imports and metric names

python scripts/07_evaluate.py
```

### Step 13: Register in ExploitGym

Edit `exploitgym/src/exploitgym/config.py`:

```python
AgentConfig(
    name="<vuln>_agent",
    vuln_type="<vuln>",
    package="<vuln>_ai",
    project_root=PLAYGROUND / "<vuln>-ai",
    model_path="models/<vuln>-qwen1.5b-v1/final",
    contexts_yaml="data/contexts/<vuln>_contexts.yaml",
    venv_ml=".venv-ml",
),
```

Add chain rules in `CHAIN_RULES`:
```python
CHAIN_RULES["<vuln>"] = ["related_vuln_1", "related_vuln_2"]
```

Add routing keywords in `exploitgym/src/exploitgym/router.py`:
```python
("<vuln>", [
    r"<vuln>",
    r"related.?keyword",
    r"another.?pattern",
]),
```

### Step 14: Commit and test

```bash
git add .
git commit -m "feat: complete <vuln> AI project"

# Test via ExploitGym
cd ../exploitgym
python scripts/run.py --agent <vuln> "description of context" -n 5
```

## Oracle design patterns

The oracle is the most critical design decision. Here are proven patterns:

| Vulnerability | Oracle Type | Implementation |
|--------------|------------|----------------|
| XSS | Browser execution | Playwright: does `alert()` fire? |
| SSRF | Callback listener | Local HTTP listener: does server connect? |
| SQLi | Database query | In-memory SQLite: does injection change results? |
| CMDi | Subprocess | Does a marker file get created? |
| LFI | File read | Does the target file content appear? |
| XXE | Structure check | Does XML entity resolve to external content? |
| SSTI | Template eval | Does `{{7*7}}` evaluate to `49`? |
| OpenRedirect | URL parser | Does redirect target external domain? |
| CRLF | Response parse | Do injected headers appear? |

### Key principle

**Only train on payloads that pass the oracle.** If your oracle is wrong, your model learns wrong patterns. The oracle IS the ground truth.

## Checklist

- [ ] Created project structure
- [ ] Copied generic modules (prompt, pair_schema, splits)
- [ ] Defined context taxonomy (locations + filters)
- [ ] Implemented filter functions
- [ ] Built the oracle (most important!)
- [ ] Created payload corpus (30+ payloads)
- [ ] Created context YAML (15+ contexts)
- [ ] Pipeline scripts working (02 → 04, gates pass)
- [ ] Tests passing
- [ ] ML venv set up (torch + CUDA)
- [ ] Training modules copied and adapted
- [ ] Model trained (T1 ≥60%)
- [ ] Generate CLI working
- [ ] Eval harness working
- [ ] Registered in ExploitGym config
- [ ] Added routing keywords
- [ ] Committed
