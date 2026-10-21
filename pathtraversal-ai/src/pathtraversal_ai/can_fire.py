"""Static 'can this payload plausibly trigger path traversal / LFI?' heuristic."""
from __future__ import annotations

import re

# Directory traversal markers (../, ..\, encoded variants).
_TRAVERSAL = re.compile(r"\.\.[\\/]|%2e%2e[\\/]|%2e%2e%2f|%2f|%5c|\.\.\\/")

# Absolute Unix targets commonly sought by traversal payloads.
_ABSOLUTE_UNIX = re.compile(
    r"^/(etc|proc|var|root|home|tmp|opt|usr|windows|Windows)", re.IGNORECASE
)

# Windows drive-letter absolute path (C:\..., C:/...).
_WINDOWS_DRIVE = re.compile(r"^[a-zA-Z]:[\\/]", re.IGNORECASE)

# PHP wrapper schemes used in LFI.
_PHP_WRAPPERS = re.compile(
    r"^(php|file|data|zip|phar|expect|input)://", re.IGNORECASE
)

# Encoded traversal markers.
_ENCODED = re.compile(r"%2e|%2f|%5c|%c0%af|%252e|%252f", re.IGNORECASE)


def can_fire(payload: str, location: str) -> bool:
    """Return True if the payload looks like it could trigger path traversal or LFI."""
    if not payload or not payload.strip():
        return False
    p = payload.strip()
    if _TRAVERSAL.search(p):
        return True
    if _ABSOLUTE_UNIX.match(p):
        return True
    if _WINDOWS_DRIVE.match(p):
        return True
    if _PHP_WRAPPERS.match(p):
        return True
    if _ENCODED.search(p):
        return True
    # A relative path with a dot-segment (./) is a weak traversal signal.
    return bool("./" in p or ".\\" in p)
