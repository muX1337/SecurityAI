"""Static 'can this payload plausibly trigger a CRLF / response injection?' heuristic.

A payload plausibly fires if, after no filtering, it contains EITHER:
  - a CRLF/CR/LF control sequence (literal \\r\\n, \\r, \\n, or the URL-encoded
    forms %0d%0a / %0d / %0a / double-encoded %25... variants / unicode
    overlong %E5%98%8A%0A form), AND
  - an injection marker: a header keyword (Set-Cookie, Location, Content-Type,
    Content-Length, X-*, Host) or HTML/body content (so response-body / response
    splitting cases count).

This is a cheap pre-filter. The authoritative ground truth is the oracle's
check_fires, which actually simulates HTTP response construction and parsing.
"""
from __future__ import annotations

import re

# Any control or encoded newline that could split an HTTP header line.
_NEWLINE_PATTERNS = [
    re.compile(p, re.IGNORECASE)
    for p in (
        r"\r\n", r"\r", r"\n",
        r"%0d%0a", r"%0d", r"%0a",
        r"%250d%250a", r"%250d", r"%250a",
        r"%25250d", r"%25250a",
        r"%E5%98%8A", r"%E5%98%8D",  # unicode overlong U+000A / U+000D
    )
]

# An injection marker: a header directive or body content following the split.
_INJECTION_MARKER = re.compile(
    r"(set-cookie|location:|content-type|content-length|x-injected|x-forwarded-for|host:|"
    r"<html|<script|<body|<img|<iframe|response splitting|alert\()",
    re.IGNORECASE,
)

# Pure-control-only payloads (just "%0d%0a") with no marker still split headers
# but inject nothing useful — treat a bare CRLF with no following content as
# not firing. The marker requirement enforces that.

# Known-benign tokens that are explicitly not injections.
_BENIGN = {"test_input", "hello_world", "normal_value"}


def can_fire(payload: str, location: str = "") -> bool:
    """Return True if the payload plausibly triggers an HTTP response injection."""
    if not payload or not payload.strip():
        return False
    if payload.strip() in _BENIGN:
        return False
    has_newline = any(p.search(payload) for p in _NEWLINE_PATTERNS)
    has_marker = bool(_INJECTION_MARKER.search(payload))
    return has_newline and has_marker
