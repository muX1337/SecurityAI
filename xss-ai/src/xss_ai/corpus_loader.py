"""Load and normalize raw XSS payload corpora."""
from __future__ import annotations

from pathlib import Path

# Files inside these corpora that contain XSS payloads.
SECLISTS_XSS_SUBPATHS = (
    "Fuzzing/XSS/XSS-BruteLogic.txt",
    "Fuzzing/XSS/XSS-Jhaddix.txt",
    "Fuzzing/XSS/XSS_.txt",
    "Fuzzing/XSS/XSS_Payloads.txt",
    "Fuzzing/XSS/Xss.txt",
    "Fuzzing/XSS/PortSwiggerXSS.txt",
    "Fuzzing/XSS-Polyglots/",
    "Fuzzing/XSS-BruteLogic/",
    "Fuzzing/SQLi/Generic-BlindSQLi.fuzz.txt",  # excluded below; listed to show we filter
)
PATT_XSS_PATH = "PayloadsAllTheThings/XSS Injection/Intruders"


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


def load_all_corpora(raw_dir: Path) -> list[str]:
    """Load SecLists XSS files + PayloadsAllTheThings XSS dir, deduped."""
    raw_dir = Path(raw_dir)
    seen: set[str] = set()
    out: list[str] = []

    seclists = raw_dir / "SecLists"
    if seclists.is_dir():
        for rel in SECLISTS_XSS_SUBPATHS:
            p = seclists / rel
            if p.is_file():
                for payload in load_payloads_from_file(p):
                    if payload not in seen:
                        seen.add(payload)
                        out.append(payload)
            elif p.is_dir():
                for payload in load_payloads_from_dir(p):
                    if payload not in seen:
                        seen.add(payload)
                        out.append(payload)
        # Fallback: sweep the whole Fuzzing/XSS tree
        xss_tree = seclists / "Fuzzing" / "XSS"
        if xss_tree.is_dir():
            for payload in load_payloads_from_dir(xss_tree):
                if payload not in seen:
                    seen.add(payload)
                    out.append(payload)

    patt = raw_dir / "PayloadsAllTheThings" / "XSS Injection"
    if patt.is_dir():
        for payload in load_payloads_from_dir(patt):
            if payload not in seen:
                seen.add(payload)
                out.append(payload)

    return out
