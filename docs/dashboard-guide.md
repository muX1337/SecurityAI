# Dashboard Guide

Web UI for the whole SecurityAI stack: model status, the message board,
lab containers, and model management — all in one place.

```bash
cd exploitgym
.venv/Scripts/python scripts/dashboard.py          # → http://127.0.0.1:9000
.venv/Scripts/python scripts/dashboard.py --port 9001 --reload   # dev mode
```

The server is a FastAPI app (`src/exploitgym/dashboard/`) reading the same
SQLite board (`exploitgym.db`) the agents write to — no extra setup.

## Tabs

### Overview

- **Stats row** — targets, findings, verified, messages (live counts from the board)
- **Model cards** — one per agent with T1 score, active version, availability
- **Quick Test** — describe an injection context in natural language, the task
  router picks the right agent(s), runs them in a background thread and streams
  the log into the page
- **Recent Activity** — combined feed of findings (🔥 = oracle-verified) and
  agent messages, with a **Fired on** column showing the target URL each
  payload succeeded on

Quick Test options:

| Field | Meaning |
|-------|---------|
| Task text | Natural-language context description (same input the agents train on) |
| Target URL | Optional; registered on the board and linked from every finding |
| auto-route | Router classifies the task → correct agent(s) |
| all agents | Runs every available agent |
| specific agent | Runs just that one |
| swarm | Event-driven dispatch — findings cascade to subscribed agents; the run log streams the event cascade |

### Message Board

Sub-tabs: **Targets** · **Findings** · **Messages** · **Chains** · **Swarm** ·
**Patterns**, plus a global search (payloads, messages, target URLs), a live
toggle (5s auto-refresh), and a **⬇ Report** download (markdown /
HackerOne / Bugcrowd / JSON from verified findings). The **Swarm** sub-tab
shows the coordination state: active work claims (who's on which target,
when the lease expires) and recent payload attempts with fired/miss
results. The **Patterns** sub-tab mines the attempts log cross-target:
agent success rates, payload-family effectiveness, context winners, and
untested targets.

Every finding row shows the full picture of *where* it succeeded:

| Column | Content |
|--------|---------|
| Payload | What the model generated |
| Context | The injection context description the payload was generated for |
| Fired on | Target URL (clickable, full URL on hover) |
| Verified | Only oracle-confirmed payloads are marked 🔥 |

### Labs

**Recon Crawler** card — crawl a seed URL (same-origin, depth-limited);
discovered links and forms become swarm targets, optionally auto-hunted
(**hunt** checkbox). Scope-gated; progress streams into the log.

Docker management for the vulnerable apps: **DVWA** (8080), **OWASP Juice
Shop** (3001), **SSRF Lab** (9099). Start/Stop/Restart per lab, state read
from `docker ps`. Containers are reused (`docker start`), not recreated —
so DVWA keeps its setup and Juice Shop keeps its score.

### Models

**System** section on top — hardware and usable models at a glance:

- GPU (name + VRAM used/total, via `nvidia-smi`), CPU cores, RAM, disk space
- **Usable base models** — everything in the local HuggingFace cache
  (candidates for training new agents)
- **Cloud AI** — first provider live: **Haimaker / z-ai/glm-5.3** (OpenAI-compatible).
  Shows which provider API keys are configured (presence only, values are never
  read or exposed): Haimaker, OpenAI, Anthropic, Google, Groq, OpenRouter,
  Mistral, HF. **Test** does a one-call round-trip.
  Cloud usage: when a task routes to a vulnerability type with **no trained
  local model** (e.g. buffer overflow, format string), the runner asks a
  **fallback generator** for candidate payloads and posts them as
  **unverified** findings — clearly marked, never oracle-confirmed.

  Fallback provider order (local-first):

  1. **Local** (default): a cached HF base model (default
     `Qwen/Qwen3-4B`, override via `LOCAL_FALLBACK_MODEL`) runs inside an
     agent project's `.venv-ml` — findings are posted as
     `local_qwen3-4b`. Needs GPU; loads the model per call.
  2. **Cloud** (Haimaker GLM-5.3): only used when no `.venv-ml` is found
     *and* the cloud is enabled + key configured (`cloud_glm53`).
  Configure by setting `HAIMAKER_API_KEY` in the environment or in a
  gitignored `.env` at the repo root (`cp .env.example .env`).

  **Disabling** — the toggle is persisted in the board DB (survives restarts):

  ```bash
  python scripts/cloud.py status    # key configured? enabled? connection ok?
  python scripts/cloud.py disable   # runner + dashboard skip the cloud entirely
  python scripts/cloud.py enable
  ```

  Or via the dashboard Cloud card (**Disable/Enable** button) /
  `PUT /api/system/cloud-enabled {"enabled": false}`. When disabled, no API
  calls are attempted at all.

Table of all 9 agents with a **Ctx** column (number of context types the
model is trained for — hover for the full list). **Details** opens per-model
info:

- All trained versions with size, training date, and which one is active
- **Activate** — swaps the active model version (rewrites `config.py` and the
  in-memory registry; no server restart needed)
- **Retrain** — runs `train.py` in the project's `.venv-ml` as a background
  job (up to 4h); status is polled live in the page
- Training-data breakdown per `.jsonl` file and the latest eval report score

**Batch retraining** — the card above the models table retrains all (or
selected) agents on a new base model:

- Base-model picker lists the local HF cache, plus free-text for any HF id
- Versions are named automatically after the model family
  (`Qwen/Qwen3-4B` → `ssrf-qwen3-4b-v1`, next free number per agent)
- Strictly **sequential** (one GPU) — a full batch of 9 takes a day+;
  progress is polled live, failures don't stop the batch
- Cloud models (GLM-5.3) can't be fine-tuned — pick a checkpoint that fits
  in VRAM

CLI equivalent (also supports `--dry-run`):

```bash
python scripts/retrain_all.py --base-model Qwen/Qwen3-4B --dry-run
python scripts/retrain_all.py --base-model Qwen/Qwen3-4B --agents xss,ssrf
```

Under the hood, each project's train script reads `BASE_MODEL_ID` and
`RETRAIN_VERSION` from the environment.

## API

Everything the UI does is also a plain HTTP endpoint (interactive docs at
`/docs`):

```
# Overview
GET  /api/models                        all agents + scores + versions
GET  /api/stats                         board statistics
GET  /api/findings?limit=20             recent findings
GET  /api/health                        availability check

# Message board
GET  /api/board/targets                 targets with finding counts
GET  /api/board/findings?vuln_type=xss&verified=true
     → payload + context_description + target_url + target_method per finding
GET  /api/board/messages?from_agent=…   inter-agent messages
GET  /api/board/chains                  cross-vuln chain events
GET  /api/board/search?q=…              search across all tables
GET  /api/board/activity?limit=20       combined activity feed

# Labs
GET  /api/labs                          lab list + container state
POST /api/labs/{id}/start|stop|restart

# Models
GET  /api/models/{vuln}                 details: versions, data, eval
PUT  /api/models/{vuln}/active          {"version": "xss-qwen1.5b-v3"}
POST /api/models/{vuln}/retrain         → job_id
GET  /api/models/jobs/{job_id}          retrain status + log tail

# Agent runs
POST /api/run                           {"task": "…", "url": "…", "agents": ["xss"], "n": 5}
GET  /api/run/status?run_id=…           progress + log
POST /api/run/{run_id}/cancel

# System
GET  /api/system                        GPU/CPU/RAM/disk, base models, cloud-key status
GET  /api/system/cloud-test             one-call round-trip to the cloud provider
PUT  /api/system/cloud-enabled          {"enabled": false} — persist cloud on/off
GET  /api/scope                         active scope policy (mode, allow/deny)
```

## What gets recorded per finding

When an agent run produces a finding, the board stores:

- `payload` — what the model generated
- `verified` — whether the oracle confirmed it fires
- `context_description` — the injection context it was generated for
  (stamped on by `run_agent` before results are posted)
- `target_id` → the target's `url`, `method`, and `params`

To query it directly:

```sql
SELECT f.vuln_type, f.payload, f.context_description, t.url, f.created_at
FROM findings f JOIN targets t ON f.target_id = t.id
WHERE f.verified = 1
ORDER BY f.created_at DESC;
```

Note: findings recorded before 2026-08-29 have an empty `context_description`
(it wasn't captured then).

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Agent shows `offline` | Model weights missing — check the project's `models/` dir, or retrain (Models tab) |
| Lab won't start | `docker ps -a --filter name=<container>` for the error, then check the port isn't taken |
| Empty board | Dashboard reads `exploitgym/exploitgym.db`; run an agent once to populate it |
| Run hangs in `running` | Agent subprocesses time out after 120s each; check `GET /api/run/status` log lines |
