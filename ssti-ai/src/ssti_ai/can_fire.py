"""Static 'can this payload plausibly trigger SSTI?' heuristic.

A payload can plausibly fire at a given location if it contains an expression
delimiter that the target template engine evaluates, OR it is a known generic
probe (e.g. a math expression in a recognized syntax). Benign strings that no
engine would interpret are rejected.

This is a cheap pre-filter used by the filter harness to discard dead payloads
before the (slightly heavier) oracle evaluation. The oracle is the final
arbiter of whether a payload actually evaluates.
"""
from __future__ import annotations

# Per-location expression markers that the corresponding engine would interpret.
_ENGINE_MARKERS: dict[str, tuple[str, ...]] = {
    "jinja2_body": ("{{", "{%"),
    "twig_body": ("{{", "{%"),
    "freemarker_body": ("${", "<#"),
    "velocity_body": ("$"),
    "mako_body": ("${"),
}

# Generic expression syntaxes that any of the engines might evaluate and that
# we treat as fireable probes regardless of location (e.g. ERB/JS-style used in
# cross-engine fuzzing). Kept deliberately narrow to avoid false positives.
_GENERIC_SYNTAX = (
    "<%=",   # ERB / EJS
    "#{",    # Ruby / Thymeleaf
    "*{",    # Thymeleaf
)

# Substrings that, while possibly reflected, are not template expressions.
_BENIGN = {"hello world", "test_input"}


def can_fire(payload: str, location: str) -> bool:
    """Return True if the payload plausibly triggers SSTI at `location`."""
    if not payload or not payload.strip():
        return False
    payload = payload.strip()
    if payload.lower() in _BENIGN:
        return False

    # Engine-specific markers for this location.
    markers = _ENGINE_MARKERS.get(location, ())
    if any(m in payload for m in markers):
        return True

    # Generic cross-engine syntaxes.
    return bool(any(s in payload for s in _GENERIC_SYNTAX))
