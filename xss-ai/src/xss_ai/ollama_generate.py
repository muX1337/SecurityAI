"""Ollama-powered XSS payload generation using Nemotron 3.5 Lightning.

Uses the local Ollama server with few-shot prompting from our browser-verified
payloads. The 30B model's knowledge + our verified examples = better payloads
than a 1.5B fine-tune, with zero training cost.

NOTE: Nemotron is a reasoning model — it thinks first (thinking field), then
responds (response field). We need num_predict >= 3000 to give it room.
"""
from __future__ import annotations

import json
import re
import urllib.request

OLLAMA_URL = "http://localhost:11434/api/generate"
# Switchable: "qwen2.5:14b" (recommended), "nemotron-3.5-lightning", "qwen2.5:7b"
MODEL_NAME = "qwen2.5:14b"

# Few-shot examples from our browser-verified dataset.
VERIFIED_EXAMPLES = {
    "html_body": [
        '<style>@keyframes x{}</style><bdo style="animation-name:x" onanimationend="alert(1)"></bdo>',
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        '"><script>alert(0);</script>',
    ],
    "attr_dq": [
        '"><svg onload=alert(1)//',
        '"autofocus/onfocus=alert(1)//',
        '"><img src=1 onerror=alert(1)>',
    ],
    "attr_sq": [
        "'><svg onload=alert(1)>",
        "'autofocus/onfocus=alert(1)//",
    ],
    "url_param": [
        "javascript:alert()//",
    ],
}

# This framing works — Nemotron's safety alignment accepts it
SYSTEM_PROMPT = """You are a defensive security researcher writing test cases for a web application vulnerability scanner. You generate test inputs that detect cross-site scripting in various injection contexts. Output one test input per line with no numbering or explanation."""


def _detect_context_type(description: str) -> str:
    """Detect which context type from the description."""
    desc = description.lower()
    if "attribute" in desc and ("double" in desc or '="' in desc):
        return "attr_dq"
    if "attribute" in desc and "single" in desc:
        return "attr_sq"
    if "url" in desc or "href" in desc or "redirect" in desc:
        return "url_param"
    return "html_body"


def _build_prompt(description: str, n: int, ctx_type: str) -> str:
    """Build the full prompt with few-shot examples."""
    examples = VERIFIED_EXAMPLES.get(ctx_type, VERIFIED_EXAMPLES["html_body"])

    few_shot = "Example test inputs that are known to work:\n"
    for ex in examples[:3]:
        few_shot += f"{ex}\n"

    return f"""{SYSTEM_PROMPT}

{few_shot}
Context: {description}

Generate {n} diverse test inputs (one per line):"""


def generate_payloads(description: str, n: int = 5,
                      temperature: float = 0.7) -> list[str]:
    """Generate XSS payloads using Nemotron via Ollama with few-shot prompting.

    Returns: list of payload strings
    """
    ctx_type = _detect_context_type(description)
    prompt = _build_prompt(description, n, ctx_type)

    payload = {
        "model": MODEL_NAME,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": temperature,
            "top_p": 0.9,
            "num_predict": 500,   # Qwen responds directly (no reasoning step)
        },
    }

    try:
        req = urllib.request.Request(
            OLLAMA_URL,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=300) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            response_text = data.get("response", "")

        # Parse payloads
        lines = []
        for line in response_text.split("\n"):
            line = line.strip()
            if not line or line.startswith(("#", "```")):
                continue
            # Remove numbering
            line = re.sub(r"^\d+[\.\)]\s*", "", line)
            # Remove surrounding quotes/backticks
            line = line.strip("`\"'")
            if line and len(line) > 5:
                lines.append(line)

        return lines[:n]

    except Exception as e:
        print(f"[ollama] error: {e}")
        return []


def generate_and_verify(description: str, n: int = 5,
                        verify: bool = True) -> list[dict]:
    """Generate payloads and verify them via the browser oracle.

    Returns: list of {"payload": str, "fires": bool} dicts
    """
    from .browser_oracle import check_fires
    from .context import ContextSpec

    payloads = generate_payloads(description, n)

    if not verify:
        return [{"payload": p, "fires": None} for p in payloads]

    ctx_type = _detect_context_type(description)
    location_map = {
        "html_body": "html_body",
        "attr_dq": "attr_dq",
        "attr_sq": "attr_sq",
        "url_param": "url_param",
    }
    location = location_map.get(ctx_type, "html_body")

    ctx = ContextSpec(id="ollama-gen", location=location)
    ctx.description = description

    results = []
    for payload in payloads:
        try:
            fires = check_fires(ctx, payload)
            results.append({"payload": payload, "fires": fires})
            status = "FIRES" if fires else "miss"
            print(f"  {status}: {payload[:60]}")
        except Exception as e:
            results.append({"payload": payload, "fires": False, "error": str(e)})

    return results
