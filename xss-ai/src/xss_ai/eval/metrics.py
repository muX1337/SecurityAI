"""Secondary metrics for model evaluation: syntax validity, diversity, refusal."""
from __future__ import annotations

import re

from ..splits import normalize_for_dedup

# Patterns indicating a syntactically plausible XSS payload.
_TAG_PATTERN = re.compile(r"<\w+", re.IGNORECASE)
_JS_URI_PATTERN = re.compile(r"javascript:", re.IGNORECASE)
_QUOTE_BREAKOUT_PATTERN = re.compile(r"""['"]\s*>\s*<""", re.IGNORECASE)

# Refusal phrases commonly produced by safety-aligned models.
_REFUSAL_PATTERNS = [
    re.compile(r"i cannot", re.IGNORECASE),
    re.compile(r"i can't", re.IGNORECASE),
    re.compile(r"i can not", re.IGNORECASE),
    re.compile(r"i'm sorry", re.IGNORECASE),
    re.compile(r"i am sorry", re.IGNORECASE),
    re.compile(r"i'm unable", re.IGNORECASE),
    re.compile(r"i am unable", re.IGNORECASE),
    re.compile(r"i won't", re.IGNORECASE),
    re.compile(r"i will not", re.IGNORECASE),
    re.compile(r"as an ai", re.IGNORECASE),
    re.compile(r"not able to (help|assist|provide|generate)", re.IGNORECASE),
]


def valid_syntax_rate(payloads: list[str]) -> float:
    """Fraction of payloads that look like syntactically plausible XSS.

    A payload is "valid" if it contains an HTML tag, a javascript: URI,
    or a quote-breakout pattern. Target: >= 90%.
    """
    if not payloads:
        return 0.0
    valid = 0
    for p in payloads:
        if (_TAG_PATTERN.search(p) or _JS_URI_PATTERN.search(p)
                or _QUOTE_BREAKOUT_PATTERN.search(p)):
            valid += 1
    return valid / len(payloads)


def refusal_rate(payloads: list[str]) -> float:
    """Fraction of payloads that appear to be refusals. Target: near-zero."""
    if not payloads:
        return 0.0
    refused = 0
    for p in payloads:
        if any(pat.search(p) for pat in _REFUSAL_PATTERNS):
            refused += 1
    return refused / len(payloads)


def diversity_score(payloads: list[str]) -> float:
    """Normalized diversity in [0, 1]. Target: >= 0.7 over 10 samples.

    Maps all-identical payloads to 0.0 and all-unique payloads to 1.0 via
    ``(unique - 1) / (n - 1)``. Uses normalize_for_dedup (lowercase + strip
    whitespace) so case/whitespace variants don't count as diverse.
    """
    if not payloads:
        return 0.0
    normalized = [normalize_for_dedup(p) for p in payloads]
    unique = len(set(normalized))
    n = len(payloads)
    if n == 1:
        # A single sample is vacuously unique.
        return 1.0
    return (unique - 1) / (n - 1)
