"""Static 'can this URL plausibly trigger SSRF?' heuristic."""
from __future__ import annotations

import re
from urllib.parse import urlparse

_HAS_SCHEME = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", re.IGNORECASE)
_SSRF_SCHEMES = {"http", "https", "file", "gopher", "dict", "ftp", "ldap", "tftp"}


def can_fire(url: str, location: str) -> bool:
    """Return True if the URL plausibly triggers an SSRF when fetched."""
    if not url or not url.strip():
        return False
    url = url.strip()
    if not _HAS_SCHEME.match(url):
        return False
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() not in _SSRF_SCHEMES:
            return False
        if not parsed.netloc and parsed.scheme not in ("file",):
            return False
    except Exception:
        return False
    return True
