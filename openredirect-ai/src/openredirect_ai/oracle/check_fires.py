"""Open redirect oracle: check_fires(ctx, payload) -> bool.

Open redirect ground truth is URL-parser based: the oracle applies the context's
filters to the payload, then checks whether the resulting URL would redirect to
an external domain. No callback listener is required.
"""
from __future__ import annotations

from urllib.parse import urlparse

from ..context import ContextSpec, simulate_reflection

# Hosts that count as "internal" (the app, localhost, loopback).
_INTERNAL_HOSTS = frozenset({"localhost", "127.0.0.1", "app.com"})


def _netloc_external(netloc: str) -> bool:
    host = netloc.split("@")[-1].split(":")[0].lower().strip("[]")
    if not host:
        return False
    return host not in _INTERNAL_HOSTS


def check_fires(ctx: ContextSpec, payload: str) -> bool:
    """Return True if the payload would redirect to an external domain after filters."""
    filtered = simulate_reflection(ctx, payload)
    if not filtered:
        return False
    return check_url_fires(filtered)


def check_url_fires(filtered: str) -> bool:
    """Return True if a (already-filtered) URL would redirect to an external domain."""
    s = filtered.strip()
    if not s:
        return False
    # Protocol-relative URL -> external if the host is not internal.
    if s.startswith("//"):
        host_part = s[2:].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        return _netloc_external(host_part)
    # Absolute scheme URL.
    if "://" in s:
        try:
            parsed = urlparse(s)
            if parsed.netloc:
                return _netloc_external(parsed.netloc)
        except Exception:
            pass
    return False
