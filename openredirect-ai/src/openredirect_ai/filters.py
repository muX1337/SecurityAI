"""Open redirect URL filter registry: each filter models ONE server-side URL check.

Each filter takes (payload, app_domain) and returns the (possibly modified)
payload string, or "" if the payload is rejected. Filters chain in order; an
empty intermediate result short-circuits to rejection.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from urllib.parse import unquote, urlparse

FILTERS: dict[str, Callable[[str, str], str]] = {}


def register(name: str) -> Callable[[Callable[[str, str], str]], Callable[[str, str], str]]:
    def deco(fn: Callable[[str, str], str]) -> Callable[[str, str], str]:
        FILTERS[name] = fn
        return fn
    return deco


def get_filter(name: str) -> Callable[[str, str], str]:
    if name not in FILTERS:
        raise KeyError(f"unknown filter {name!r}; registered: {sorted(FILTERS)}")
    return FILTERS[name]


def apply_filters(payload: str, filter_names: list[str], app_domain: str = "app.com") -> str:
    out = payload
    for name in filter_names:
        out = get_filter(name)(out, app_domain)
        if out == "":
            return ""
    return out


@register("block_absolute_url")
def block_absolute_url(payload: str, app_domain: str = "app.com") -> str:
    """Reject payloads starting with http:// or https:// (absolute URLs)."""
    if re.match(r"^\s*https?://", payload, re.IGNORECASE):
        return ""
    return payload


@register("require_same_domain")
def require_same_domain(payload: str, app_domain: str = "app.com") -> str:
    """Only allow same-domain redirects: reject absolute/protocol-relative/external hosts.

    A same-domain redirect must be a relative path or a same-host absolute URL.
    Anything with an external netloc, or a protocol-relative URL, is rejected.
    """
    s = payload.strip()
    # Protocol-relative URLs (//evil.com) are external.
    if s.startswith("//"):
        return ""
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", s, re.IGNORECASE):
        try:
            parsed = urlparse(s)
            host = (parsed.hostname or "").lower()
            if host and host != app_domain.lower() and not host.endswith("." + app_domain.lower()):
                return ""
        except Exception:
            return ""
    # Relative paths (starting with / but not //) are allowed.
    return payload


@register("block_protocol_relative")
def block_protocol_relative(payload: str, app_domain: str = "app.com") -> str:
    """Reject protocol-relative URLs (starting with //)."""
    if payload.strip().startswith("//"):
        return ""
    return payload


@register("block_at_symbol")
def block_at_symbol(payload: str, app_domain: str = "app.com") -> str:
    """Reject URLs containing the @ symbol (userinfo / authority confusion)."""
    if "@" in payload:
        return ""
    return payload


@register("block_backslash")
def block_backslash(payload: str, app_domain: str = "app.com") -> str:
    """Reject URLs containing backslashes."""
    if "\\" in payload:
        return ""
    return payload


@register("url_decode")
def url_decode(payload: str, app_domain: str = "app.com") -> str:
    """URL-decode the input before returning it for further checks."""
    return unquote(payload)


@register("block_dotdot")
def block_dotdot(payload: str, app_domain: str = "app.com") -> str:
    """Reject URLs containing ../ sequences."""
    if "../" in payload or "..\\" in payload:
        return ""
    return payload


@register("allowlist_paths")
def allowlist_paths(payload: str, app_domain: str = "app.com") -> str:
    """Only allow specific path prefixes: reject absolute/protocol-relative/external.

    Same intent as require_same_domain but stricter semantics for the allowlist
    case: anything that looks like an absolute external URL or a // host is
    rejected; only same-site path-like values survive.
    """
    s = payload.strip()
    if s.startswith("//"):
        return ""
    if re.match(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://", s, re.IGNORECASE):
        try:
            parsed = urlparse(s)
            host = (parsed.hostname or "").lower()
            if host and host != app_domain.lower():
                return ""
        except Exception:
            return ""
    return payload
