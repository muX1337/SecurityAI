"""Static 'can this payload still fire?' heuristic.

Predicts whether a payload would auto-fire (execute on page load WITHOUT user
interaction) in a given injection location. Browser oracle is ground truth; this
heuristic exists only as a cheap pre-filter for the filter harness.

Key accuracy fix (v1.5): only AUTO-FIRING event handlers count. Handlers like
onmouseover/onclick/onfocusin need user interaction and will never fire in a
headless browser on load, so they must not be predicted as firing.
"""
from __future__ import annotations

import re

# Event handlers that fire automatically on page load, no interaction needed.
# onload/onerror are the workhorses. The others need a companion condition.
AUTO_FIRING_HANDLERS: frozenset[str] = frozenset({
    "onload",
    "onerror",
    "onfocus",       # ONLY counts when autofocus/tabindex is also present (checked below)
    "ontoggle",      # ONLY counts on <details open> (checked below)
    "onanimationstart",  # ONLY counts with a CSS animation style (checked below)
    "onanimationend",
})

# Sinks that indicate code execution when present.
SINKS = re.compile(
    r"\b(alert|confirm|prompt|eval|fetch|document\.|window\.|location\."
    r"setTimeout|setInterval|Function\()\b",
    re.IGNORECASE,
)
# Any on*= assignment (used to detect handler presence, then filtered to auto-firing).
# Captures the full handler name INCLUDING the "on" prefix so names are comparable
# to AUTO_FIRING_HANDLERS (e.g. "onload", "onerror").
_ANY_HANDLER = re.compile(r"\b(on\w+)\s*=", re.IGNORECASE)
SCRIPT_TAG = re.compile(r"<script[^>]*>", re.IGNORECASE)


def _has_sink(s: str) -> bool:
    return bool(SINKS.search(s))


def _handler_names(s: str) -> set[str]:
    """Return the lowercased event-handler names present (onX= -> onx)."""
    return {m.group(1).lower() for m in _ANY_HANDLER.finditer(s)}


def _has_auto_firing_handler(s: str) -> bool:
    """True if s carries an event handler that will auto-fire on load."""
    names = _handler_names(s)
    # onload / onerror / onanimationstart / onanimationend: fire unconditionally
    # (onanimation* assume a CSS animation is defined; we accept the handler and
    #  let the browser oracle reject the rare cases where no animation is present).
    unconditional = names & {"onload", "onerror", "onanimationstart", "onanimationend"}
    if unconditional:
        return True
    # onfocus: needs autofocus or tabindex to receive focus automatically
    if "onfocus" in names and re.search(r"\b(autofocus|tabindex)\b", s, re.IGNORECASE):
        return True
    # ontoggle: needs <details ... open>
    return bool("ontoggle" in names and re.search(r"<details[^>]*\bopen\b", s, re.IGNORECASE))


def _can_fire_html_body(s: str) -> bool:
    if not s:
        return False
    if SCRIPT_TAG.search(s) and _has_sink(s):
        return True
    return bool(_has_auto_firing_handler(s) and _has_sink(s))


def _can_fire_attr(s: str, quote: str) -> bool:
    # Must break out of the attribute (closing quote + >), then inject into body.
    if quote not in s:
        return False
    idx = s.find(quote)
    rest = s[idx + 1:]
    # The injected content after breakout follows html_body rules.
    return _can_fire_html_body(rest)


def _can_fire_js_string(s: str, quote: str) -> bool:
    # Breakout: quote followed by ; or ) etc., then a sink.
    m = re.search(re.escape(quote) + r"\s*[;)\n]", s)
    if not m:
        return False
    rest = s[m.end():]
    return _has_sink(rest)


def _can_fire_url(s: str) -> bool:
    # javascript: URI with a sink, or a breakout to an auto-firing tag.
    if re.search(r"javascript:", s, re.IGNORECASE) and _has_sink(s):
        return True
    return _can_fire_html_body(s)


def _can_fire_html_comment(s: str) -> bool:
    if "-->" in s:
        rest = s[s.find("-->") + 3:]
        return _can_fire_html_body(rest)
    return False


_DISPATCH = {
    "html_body": _can_fire_html_body,
    "attr_dq": lambda s: _can_fire_attr(s, '"'),
    "attr_sq": lambda s: _can_fire_attr(s, "'"),
    "js_string_sq": lambda s: _can_fire_js_string(s, "'"),
    "js_string_dq": lambda s: _can_fire_js_string(s, '"'),
    "url_param": _can_fire_url,
    "html_comment": _can_fire_html_comment,
}


def can_fire(filtered_payload: str, location: str) -> bool:
    """Return True if filtered_payload plausibly auto-fires in `location`."""
    fn = _DISPATCH.get(location)
    if fn is None:
        raise ValueError(f"no can-fire rule for location {location!r}")
    return bool(fn(filtered_payload))
