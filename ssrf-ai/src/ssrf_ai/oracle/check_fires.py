"""SSRF oracle: check_fires(ctx, payload) -> bool.

Rewrites the payload URL to point at a local listener, fetches it via httpx,
and checks if the listener recorded a hit. If yes, the SSRF "fired".
"""
from __future__ import annotations

from typing import Self
from urllib.parse import urlparse, urlunparse

import httpx

from ..can_fire import can_fire
from ..context import ContextSpec, simulate_reflection
from .listener import CallbackListener


def _rewrite_to_listener(url: str, listener_host: str, listener_port: int) -> str:
    """Replace the URL's host:port with the listener's address."""
    try:
        parsed = urlparse(url)
        if not parsed.scheme:
            return url
        new_netloc = f"{listener_host}:{listener_port}"
        return urlunparse(parsed._replace(netloc=new_netloc))
    except Exception:
        return url


class OracleSession:
    """Context manager keeping a callback listener running for batch checks."""

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
        """Return True if the payload triggers a fetch to the listener."""
        if not can_fire(payload, ctx.location):
            return False

        if self._listener:
            self._listener.clear_hits()

        filtered = simulate_reflection(ctx, payload)
        if not filtered:
            return False

        rewritten = _rewrite_to_listener(filtered, "127.0.0.1", self.listener_port)

        try:
            with httpx.Client(follow_redirects=ctx.allows_redirects, timeout=3.0,
                              verify=False) as client:
                client.get(rewritten)
        except Exception:
            pass

        return bool(self._listener and self._listener.hit_count > 0)


def check_fires(ctx: ContextSpec, payload: str) -> bool:
    """Standalone check_fires — creates an ephemeral OracleSession per call."""
    with OracleSession() as session:
        return session.check_fires(ctx, payload)
