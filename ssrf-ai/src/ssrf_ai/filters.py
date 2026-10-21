"""SSRF URL filter registry: each filter models ONE server-side URL check."""
from __future__ import annotations

import ipaddress
import socket
from collections.abc import Callable
from urllib.parse import urlparse

FILTERS: dict[str, Callable[[str], str]] = {}


def register(name: str) -> Callable[[Callable[[str], str]], Callable[[str], str]]:
    def deco(fn: Callable[[str], str]) -> Callable[[str], str]:
        FILTERS[name] = fn
        return fn
    return deco


def get_filter(name: str) -> Callable[[str], str]:
    if name not in FILTERS:
        raise KeyError(f"unknown filter {name!r}; registered: {sorted(FILTERS)}")
    return FILTERS[name]


def apply_filters(url: str, filter_names: list[str]) -> str:
    out = url
    for name in filter_names:
        out = get_filter(name)(out)
        if out == "":
            return ""
    return out


_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
]

_LOCALHOST_ALIASES = {
    "localhost", "0.0.0.0", "[::]", "[::1]", "[0:0:0:0:0:0:0:1]",
    "2130706433", "0x7f000001", "017700000001",
    "127.1", "127.0.1", "0", "0x0",
}

_METADATA_IPS = {"169.254.169.254", "fd00:ec2::254"}


def _extract_host(url: str) -> str:
    try:
        parsed = urlparse(url)
        host = parsed.hostname or ""
        return host.lower().strip("[]")
    except Exception:
        return ""


def _is_private_ip(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        for net in _PRIVATE_RANGES:
            if ip in net:
                return True
        return False
    except ValueError:
        return False


@register("block_private_ip")
def block_private_ip(url: str) -> str:
    host = _extract_host(url)
    if host and _is_private_ip(host):
        return ""
    return url


@register("block_localhost_aliases")
def block_localhost_aliases(url: str) -> str:
    host = _extract_host(url)
    if host in _LOCALHOST_ALIASES:
        return ""
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback:
            return ""
    except ValueError:
        pass
    return url


@register("block_metadata_ip")
def block_metadata_ip(url: str) -> str:
    host = _extract_host(url)
    if host in _METADATA_IPS:
        return ""
    return url


@register("scheme_http_only")
def scheme_http_only(url: str) -> str:
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https", ""):
            return ""
    except Exception:
        return ""
    return url


@register("block_redirects")
def block_redirects(url: str) -> str:
    return url  # flag filter, not URL transformation


@register("url_syntax_validate")
def url_syntax_validate(url: str) -> str:
    if "\n" in url or "\r" in url or "\\" in url:
        return ""
    return url


@register("dns_resolve_check")
def dns_resolve_check(url: str) -> str:
    host = _extract_host(url)
    if not host:
        return url
    try:
        ipaddress.ip_address(host)
        return url
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            for net in _PRIVATE_RANGES:
                if ip in net:
                    return ""
    except (socket.gaierror, OSError):
        pass
    return url
