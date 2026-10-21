"""Minimal SSRF-vulnerable Flask app for T3 evaluation.

Three security levels:
  - low: no filtering (fetch anything)
  - medium: block private IPs + localhost aliases
  - high: block private IPs + localhost + metadata + scheme http-only

Run: python src/labs/vuln_ssrf_app.py
  or: docker build + docker run (see Dockerfile)
"""
from __future__ import annotations

import ipaddress
import os
from urllib.parse import urlparse

import httpx
from flask import Flask, jsonify, request

app = Flask(__name__)

PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]

LOCALHOST_ALIASES = {
    "localhost", "0.0.0.0", "[::]", "[::1]",
    "2130706433", "0x7f000001",
}

METADATA_IPS = {"169.254.169.254"}


def get_security_level() -> str:
    return os.environ.get("SSRF_SECURITY", "medium")


def check_url(url: str, level: str) -> tuple[bool, str]:
    """Returns (allowed, reason)."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False, "invalid_url"

    host = (parsed.hostname or "").lower().strip("[]")

    if level in ("medium", "high"):
        # Block private IPs
        try:
            ip = ipaddress.ip_address(host)
            for net in PRIVATE_RANGES:
                if ip in net:
                    return False, "blocked_private_ip"
        except ValueError:
            pass

        # Block localhost aliases
        if host in LOCALHOST_ALIASES:
            return False, "blocked_localhost"

    if level == "high":
        # Block metadata
        if host in METADATA_IPS:
            return False, "blocked_metadata"

        # Scheme allowlist
        if parsed.scheme not in ("http", "https"):
            return False, "blocked_scheme"

    return True, "ok"


@app.route("/fetch")
def fetch():
    """Vulnerable endpoint: fetches whatever URL is given."""
    url = request.args.get("url", "")
    level = get_security_level()

    if not url:
        return jsonify({"error": "no url parameter"}), 400

    allowed, reason = check_url(url, level)
    if not allowed:
        return jsonify({"error": reason, "url": url, "security": level}), 403

    try:
        with httpx.Client(follow_redirects=True, timeout=5.0, verify=False) as client:
            resp = client.get(url)
            return jsonify({
                "status": resp.status_code,
                "body": resp.text[:1000],
                "url": url,
                "security": level,
            })
    except Exception as e:
        return jsonify({"error": str(e), "url": url, "security": level}), 502


@app.route("/health")
def health():
    return jsonify({"status": "ok", "security": get_security_level()})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "9099"))
    app.run(host="0.0.0.0", port=port, debug=False)
