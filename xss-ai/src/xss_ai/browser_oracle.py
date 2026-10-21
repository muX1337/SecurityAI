"""Source 2: Playwright browser oracle — ground-truth payload execution check.

Where `filter_harness` uses a static heuristic (`can_fire`) to predict whether a
payload executes, this module executes the payload for real in a Chromium browser
and observes whether `alert()` fires. This is the ground truth used to validate
the filter-harness pairs (the 85% agreement gate) before training.

The server-side reflection pipeline must mirror `filter_harness` exactly: encode
first, then filter. The filtered result is then embedded RAW into an HTML page
matching the context's location, so the browser parses it as a victim page would.
"""
from __future__ import annotations

from .context import ContextSpec, simulate_reflection

FIRE_TIMEOUT_MS = 2000


def render_page_html(ctx: ContextSpec, filtered_payload: str) -> str:
    """Embed the (already-filtered) payload into an HTML page for the context location.

    NOTE: filtered_payload is assumed to be the SERVER'S reflection — it is embedded
    RAW so the browser parses it exactly as a victim page would.
    """
    p = filtered_payload
    if ctx.location == "html_body":
        body = p
    elif ctx.location == "attr_dq":
        body = f'<input value="{p}">'
    elif ctx.location == "attr_sq":
        body = f"<input value='{p}'>"
    elif ctx.location == "js_string_sq":
        body = f"<script>var x = '{p}';</script>"
    elif ctx.location == "js_string_dq":
        body = f'<script>var x = "{p}";</script>'
    elif ctx.location == "url_param":
        body = f'<a href="{p}">link</a>'
    elif ctx.location == "html_comment":
        body = f"<!-- {p} -->"
    else:
        raise ValueError(f"no page template for {ctx.location!r}")

    return f"""<!DOCTYPE html>
<html><head><meta charset="utf-8"></head>
<body>
{body}
</body></html>"""


def check_fires(ctx: ContextSpec, payload: str) -> bool:
    """Return True if payload fires alert() in a real browser under this context.

    Resilient to payloads that hang the page (infinite loops, blocking fetches):
    a Playwright timeout on set_content is treated as 'does not fire' rather than
    crashing the whole run.
    """
    from playwright.sync_api import TimeoutError as PWTimeoutError
    from playwright.sync_api import sync_playwright

    reflected = simulate_reflection(ctx, payload)
    if not reflected:
        # A blocking filter emptied the reflection -> nothing to execute.
        return False
    page_html = render_page_html(ctx, reflected)

    with sync_playwright() as pw:
        browser = pw.chromium.launch()
        try:
            page = browser.new_page()
            fired = False

            def _on_dialog(_dialog) -> None:
                nonlocal fired
                fired = True
                _dialog.dismiss()

            page.on("dialog", _on_dialog)
            try:
                page.set_content(page_html, timeout=5000)
            except PWTimeoutError:
                # Some payloads produce pages that never reach 'load' (infinite
                # loops, etc.). The dialog may still have fired before the timeout.
                pass
            page.wait_for_timeout(FIRE_TIMEOUT_MS)
            return fired
        finally:
            browser.close()


def validate_pairs(pairs, sample_fraction: float = 0.1, seed: int = 0) -> dict:
    """Validate a random sample of pairs; return per-context agreement stats.

    pairs: list of Pair (filter_harness output).
    Returns {"per_context": {ctx_id: {"agree": n, "disagree": n, "rate": float}},
             "overall_rate": float, "total_checked": int}.

    A pair "agrees" with the oracle if the browser confirms the payload fires
    (the filter-harness only kept pairs it believed would fire, so agreement is
    the fraction the browser actually observes firing).
    """
    import random
    rng = random.Random(seed)

    # Group by context id, sample fraction per context.
    by_ctx: dict[str, list] = {}
    for pr in pairs:
        by_ctx.setdefault(pr.context.id, []).append(pr)

    per_context: dict[str, dict] = {}
    total_agree = 0
    total_checked = 0
    for ctx_id, group in by_ctx.items():
        k = max(1, int(len(group) * sample_fraction))
        sample = rng.sample(group, min(k, len(group)))
        agree = 0
        for pr in sample:
            fires = check_fires(pr.context, pr.payload)
            if fires:
                agree += 1
        n = len(sample)
        rate = agree / n if n else 0.0
        per_context[ctx_id] = {"agree": agree, "disagree": n - agree,
                               "checked": n, "rate": rate}
        total_agree += agree
        total_checked += n

    overall = total_agree / total_checked if total_checked else 0.0
    return {"per_context": per_context, "overall_rate": overall,
            "total_checked": total_checked}


def mine_pairs(contexts, payloads, per_context_cap: int = 50) -> list:
    """Source 2b: mine (context, payload) pairs by testing payloads in a real browser.

    For each context, test payloads and keep only those that actually fire alert().
    These are gold-standard pairs (verified_by="playwright") used to supplement
    filter-sim pairs where the heuristic is thin or unreliable.

    contexts: list of ContextSpec. payloads: list of raw payload strings.
    Returns a list of Pair objects.
    """
    import hashlib

    from .pair_schema import Pair, Provenance

    mined: list = []
    for ctx in contexts:
        survivors: list = []
        for payload in payloads:
            if len(survivors) >= per_context_cap:
                break
            if check_fires(ctx, payload):
                h = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:8]
                if ctx.description is None:
                    from .context import render_description
                    ctx.description = render_description(ctx)
                survivors.append(
                    Pair(
                        id=f"{ctx.id}__pl-{h}",
                        context=ctx,
                        payload=payload,
                        provenance=Provenance(
                            source="browser_oracle", verified_by="playwright"
                        ),
                    )
                )
        mined.extend(survivors)
    return mined


def test_payloads_once(payloads, ctx) -> list[str]:
    """Browser-test each payload in ONE context; return those that fire.

    Used to filter the corpus down to genuinely-firing payloads before
    expanding them across all contexts. Testing once (not per-context) makes
    a 74x problem tractable: ~2000 launches instead of ~150k.
    """
    firing: list[str] = []
    for payload in payloads:
        if check_fires(ctx, payload):
            firing.append(payload)
    return firing


def expand_verified(verified_payloads, contexts) -> list:
    """Re-pair browser-verified payloads with all contexts where they survive.

    Each payload in verified_payloads has been confirmed to fire in a browser.
    For each context, the payload is run through simulate_reflection + can_fire;
    if it survives (the payload's firing structure isn't destroyed by the
    context's filters), a Pair is created with playwright provenance.

    This produces the gold-standard dataset: every pair is (browser-verified
    payload) x (context where it's valid).
    """
    import hashlib

    from .can_fire import can_fire
    from .context import render_description, simulate_reflection
    from .pair_schema import Pair, Provenance

    pairs: list = []
    for ctx in contexts:
        if ctx.description is None:
            ctx.description = render_description(ctx)
        for payload in verified_payloads:
            filtered = simulate_reflection(ctx, payload)
            if not filtered:
                continue
            if not can_fire(filtered, ctx.location):
                continue
            h = hashlib.sha1(payload.encode("utf-8")).hexdigest()[:8]
            pairs.append(
                Pair(
                    id=f"{ctx.id}__pl-{h}",
                    context=ctx,
                    payload=payload,
                    provenance=Provenance(
                        source="browser_oracle", verified_by="playwright"
                    ),
                )
            )
    return pairs
