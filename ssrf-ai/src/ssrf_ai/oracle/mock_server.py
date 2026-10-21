"""Mock vulnerable server helper: applies filters and fetches a URL via httpx."""
from __future__ import annotations

import httpx

from ..context import ContextSpec, simulate_reflection


def fetch_url(ctx: ContextSpec, payload: str, timeout: float = 3.0) -> bool:
    """Apply filters and fetch the URL. Returns True if fetch succeeded."""
    filtered = simulate_reflection(ctx, payload)
    if not filtered:
        return False
    try:
        with httpx.Client(follow_redirects=ctx.allows_redirects, timeout=timeout,
                          verify=False) as client:
            resp = client.get(filtered)
            return resp.status_code < 400
    except Exception:
        return False
