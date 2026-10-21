"""Static 'can this payload plausibly trigger SQLi?' heuristic."""
from __future__ import annotations

import re

_SQL_KEYWORDS = re.compile(
    r"\b(union|select|or|and|insert|drop|update|delete|sleep|benchmark|"
    r"extractvalue|updatexml|substring|case|when|concat)\b",
    re.IGNORECASE,
)
_QUOTE_OR_COMMENT = re.compile(r"['\"]|--|#|/\*|\bor\b.*=", re.IGNORECASE)

def can_fire(payload: str, location: str) -> bool:
    """Return True if the payload looks like it could trigger SQLi."""
    if not payload or not payload.strip():
        return False
    p = payload.strip()
    # Must contain a SQL keyword or quote/comment marker
    if _SQL_KEYWORDS.search(p):
        return True
    if _QUOTE_OR_COMMENT.search(p):
        return True
    # Numeric payloads are valid for numeric contexts
    if location == "numeric":
        try:
            int(p)
            return True
        except ValueError:
            pass
    return False
