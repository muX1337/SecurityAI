"""Mock vulnerable server helper: applies filters and checks XXE effectiveness."""
from __future__ import annotations

from ..can_fire import can_fire
from ..context import ContextSpec, simulate_reflection


def fetch_url(ctx: ContextSpec, payload: str) -> bool:
    """Apply filters and check if the payload is an effective XXE. Returns True if it fires."""
    filtered = simulate_reflection(ctx, payload)
    if not filtered:
        return False
    return can_fire(filtered, ctx.location)
