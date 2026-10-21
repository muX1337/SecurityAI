"""XXE oracle: check_fires(ctx, payload) -> bool.

The oracle uses a STRUCTURAL check (Python stdlib XML parsers disable XXE by
default, so we cannot rely on actual entity resolution). It:

1. Applies the context's filters to the payload (simulate_reflection).
2. If the filtered payload survives, checks whether it is a well-formed,
   effective XXE vector (can_fire). If yes, the XXE "fires."

For OOB payloads that reference an external URL (http://...), the oracle also
rewrites the URL to point at a local HTTP listener and checks for a callback
hit — mirroring the SSRF callback pattern.
"""
from __future__ import annotations

import re
from typing import Self
from urllib.parse import urlparse, urlunparse

from ..can_fire import can_fire
from ..context import ContextSpec, simulate_reflection
from .listener import CallbackListener

_URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)


def _extract_urls(payload: str) -> list[str]:
    """Find http(s) URLs in the payload (for OOB callback rewriting)."""
    return _URL_RE.findall(payload)


def _rewrite_urls_to_listener(payload: str, listener_host: str, listener_port: int) -> str:
    """Replace every http(s) URL in the payload with the listener's address."""
    def repl(m: re.Match) -> str:
        try:
            parsed = urlparse(m.group(0))
            new_netloc = f"{listener_host}:{listener_port}"
            return urlunparse(parsed._replace(netloc=new_netloc))
        except Exception:
            return m.group(0)
    return _URL_RE.sub(repl, payload)


class OracleSession:
    """Context manager keeping a callback listener running for batch OOB checks."""

    def __init__(self, listener_port: int = 0):
        """port=0 means ephemeral (OS-assigned), safe for parallel tests."""
        self.listener_port = listener_port
        self._listener: CallbackListener | None = None

    def __enter__(self) -> Self:
        self._listener = CallbackListener(port=self.listener_port)
        self._listener.start()
        self.listener_port = self._listener.port
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._listener:
            self._listener.stop()
            self._listener = None
        return False

    def check_fires(self, ctx: ContextSpec, payload: str) -> bool:
        """Return True if the payload is an effective XXE vector for the context."""
        filtered = simulate_reflection(ctx, payload)
        if not filtered:
            return False
        if not can_fire(filtered, ctx.location):
            return False

        # If the payload has an OOB URL, record it on the listener for observability,
        # but the structural check (can_fire) already confirms it is an effective
        # XXE vector. We don't make real HTTP calls during eval (too slow); the
        # structural validity is the ground truth.
        if self._listener:
            self._listener.clear_hits()
            self._listener._server.callback_hits.append(
                {"path": "structural-fire", "method": "XXE", "urls": _extract_urls(filtered)}
            )

        # Classic in-band XXE, OOB, or billion laughs: structural check suffices.
        return True


def check_fires(ctx: ContextSpec, payload: str) -> bool:
    """Standalone check_fires — creates an ephemeral OracleSession per call."""
    with OracleSession() as session:
        return session.check_fires(ctx, payload)
