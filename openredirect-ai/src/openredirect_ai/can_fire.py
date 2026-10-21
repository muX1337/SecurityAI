"""Static 'would this URL plausibly cause an external redirect?' heuristic.

This mirrors the oracle's external-domain check, but as a fast pre-filter with
no side effects. Used by the filter harness to drop payloads that could never
redirect externally (e.g. relative paths, plain text) before recording them.
"""
from __future__ import annotations

import re
from urllib.parse import urlparse

# Hosts that count as "internal" (the app, localhost, loopback).
INTERNAL_HOSTS = frozenset({"localhost", "127.0.0.1", "app.com"})


def _netloc_external(netloc: str) -> bool:
    host = netloc.split("@")[-1].split(":")[0].lower().strip("[]")
    if not host:
        return False
    return host not in INTERNAL_HOSTS


def can_fire(url: str, location: str) -> bool:
    """Return True if the URL plausibly triggers a redirect to an external domain."""
    if not url or not url.strip():
        return False
    url = url.strip()
    # Protocol-relative (//evil.com) -> external.
    if url.startswith("//"):
        return _netloc_external(url[2:].split("/", 1)[0].split("?", 1)[0])
    # Absolute scheme URL.
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", url, re.IGNORECASE):
        try:
            parsed = urlparse(url)
            if parsed.netloc:
                return _netloc_external(parsed.netloc)
        except Exception:
            return False
    return False
