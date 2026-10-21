"""CRLF filter registry: each filter models ONE server-side input check.

Filters come in two kinds:
  - DECODE filters (url_decode, double_decode): transform the payload string
    in place and never reject. These conceptually run BEFORE block filters so
    that a server which decodes input and then checks for CRLF can be bypassed
    by double-encoding.
  - BLOCK filters (block_crlf, block_cr_only, ...): examine the (possibly
    decoded) string and return "" to reject it.

apply_filters applies all DECODE filters first (url_decode before
double_decode), then the remaining block filters in listed order. This models
the common real-world pattern: decode -> sanitize.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import unquote

FILTERS: dict[str, Callable[[str], str]] = {}

# Decode filters run before block filters regardless of their position in the
# context's filter list. Within decode filters, earlier entries run first.
_DECODE_ORDER = ("url_decode", "double_decode")


def register(name: str) -> Callable[[Callable[[str], str]], Callable[[str], str]]:
    def deco(fn: Callable[[str], str]) -> Callable[[str], str]:
        FILTERS[name] = fn
        return fn
    return deco


def get_filter(name: str) -> Callable[[str], str]:
    if name not in FILTERS:
        raise KeyError(f"unknown filter {name!r}; registered: {sorted(FILTERS)}")
    return FILTERS[name]


def apply_filters(payload: str, filter_names: list[str]) -> str:
    """Apply decode filters first, then block filters in listed order.

    Returns "" as soon as any block filter rejects (short-circuit). Decode
    filters never reject; they only transform.
    """
    names = list(filter_names)
    decode_names = [n for n in _DECODE_ORDER if n in names]
    block_names = [n for n in names if n not in _DECODE_ORDER]

    out = payload
    for name in decode_names:
        out = get_filter(name)(out)
    for name in block_names:
        out = get_filter(name)(out)
        if out == "":
            return ""
    return out


# --- Decode filters -------------------------------------------------------

@register("url_decode")
def url_decode(payload: str) -> str:
    """URL-decode the payload once."""
    try:
        return unquote(payload)
    except Exception:
        return payload


@register("double_decode")
def double_decode(payload: str) -> str:
    """URL-decode the payload twice (models servers that decode recursively)."""
    try:
        return unquote(unquote(payload))
    except Exception:
        return payload


# --- Block filters --------------------------------------------------------
# Each returns "" if the (already-decoded) payload contains the forbidden
# pattern, otherwise returns the payload unchanged.

@register("block_crlf")
def block_crlf(payload: str) -> str:
    """Block a literal CR immediately followed by LF (\\r\\n)."""
    if "\r\n" in payload:
        return ""
    return payload


@register("block_cr_only")
def block_cr_only(payload: str) -> str:
    """Block any standalone carriage return (\\r)."""
    if "\r" in payload:
        return ""
    return payload


@register("block_lf_only")
def block_lf_only(payload: str) -> str:
    """Block any standalone linefeed (\\n)."""
    if "\n" in payload:
        return ""
    return payload


_CR_PCT = re.compile(r"%0d", re.IGNORECASE)
_LF_PCT = re.compile(r"%0a", re.IGNORECASE)


@register("block_percent_0d")
def block_percent_0d(payload: str) -> str:
    """Block the URL-encoded CR token %0d (case-insensitive)."""
    if _CR_PCT.search(payload):
        return ""
    return payload


@register("block_percent_0a")
def block_percent_0a(payload: str) -> str:
    """Block the URL-encoded LF token %0a (case-insensitive)."""
    if _LF_PCT.search(payload):
        return ""
    return payload


_HEADER_KW = re.compile(r"set-cookie|location:|content-type", re.IGNORECASE)


@register("block_header_keywords")
def block_header_keywords(payload: str) -> str:
    """Block header-injection keywords (Set-Cookie, Location, Content-Type)."""
    if _HEADER_KW.search(payload):
        return ""
    return payload
