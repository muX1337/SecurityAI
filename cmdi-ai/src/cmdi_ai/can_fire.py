"""Static 'can this payload plausibly trigger command injection?' heuristic."""
from __future__ import annotations

import re

# Shell metacharacters that enable command injection.
_SHELL_METACHARS = re.compile(r"[;|&`$<>]")

# Encoded newline (URL-encoded) used for CRLF injection into commands.
_ENCODED_NEWLINE = re.compile(r"%0[ad]", re.IGNORECASE)

# Common command keywords that indicate an injection attempt.
_CMD_KEYWORDS = re.compile(
    r"\b(whoami|id|cat|ls|curl|wget|nc|bash|sh|powershell|cmd|"
    r"ping|echo|nslookup|dig|ifconfig|ipconfig|uname)\b",
    re.IGNORECASE,
)

# Substitution / expansion patterns.
_SUBSTITUTION = re.compile(r"\$\(|`")


def can_fire(payload: str, location: str) -> bool:
    """Return True if the payload looks like it could trigger command injection."""
    if not payload or not payload.strip():
        return False
    p = payload.strip()
    # Must contain a shell metacharacter, encoded newline, or command keyword.
    if _SHELL_METACHARS.search(p):
        return True
    if _ENCODED_NEWLINE.search(p):
        return True
    if _SUBSTITUTION.search(p):
        return True
    # In shell_command context, the input IS the command, so any command
    # keyword alone is a plausible injection.
    return bool(location == "shell_command" and _CMD_KEYWORDS.search(p))
