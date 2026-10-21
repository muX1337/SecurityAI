"""CMDi oracle: check_fires(ctx, payload) -> bool.

Subprocess-based oracle. Applies filters to the payload, injects it into a
vulnerable command, runs it via subprocess (bash -c if available), and checks
whether a marker file was created.

Detection strategy:
  The payload contains an injection vector (a shell metacharacter like ;, |,
  &&, &, `` ` ``, $()) followed by a command. The oracle replaces the
  attacker's command with a marker-write (``echo MARKER > path``) that uses
  the SAME injection vector. If the shell evaluates the metacharacter as a
  command separator, the marker-write runs and the marker file appears.

  Conditional operators need the base command to cooperate:
    - ``&&`` runs the second command only if the FIRST SUCCEEDS → base = ``true``
    - ``||`` runs the second command only if the FIRST FAILS    → base = ``false``
  Unconditional separators (;, |, &) run regardless → base = ``true``.

  For ``shell_command`` (input IS the command), a payload with no separator is
  a direct command: the oracle runs it and appends a marker-write chained with
  ``&&`` so the marker appears only if the command executed successfully.
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
from typing import Self

from ..can_fire import can_fire
from ..context import ContextSpec, simulate_reflection

# Marker content written to the file on successful injection.
_MARKER_CONTENT = "CMDI_ORACLE_HIT"


def _find_bash() -> str | None:
    """Locate a bash executable."""
    return shutil.which("bash")


def _bash_path(windows_path: str) -> str:
    """Convert a Windows path to a bash-friendly path (forward slashes).

    Git-bash on Windows accepts forward-slash Windows paths (C:/Users/...).
    """
    return windows_path.replace("\\", "/")


# Injection vectors, ordered by priority (longest match first).
# Each entry: (regex, vector_type) where type is "separator" or "substitution".
_VECTORS: list[tuple[re.Pattern, str]] = [
    (re.compile(r"\|\|"), "separator"),
    (re.compile(r"&&"), "separator"),
    (re.compile(r";"), "separator"),
    (re.compile(r"\|"), "separator"),
    (re.compile(r"&"), "separator"),
    (re.compile(r"\$\("), "substitution_dollar"),
    (re.compile(r"`"), "substitution_backtick"),
]


def _select_base(transformed: str) -> str:
    """Choose a base command so conditional operators evaluate correctly.

    ``||`` needs the preceding command to FAIL; everything else works with
    ``true`` (which always succeeds).
    """
    return "false" if "||" in transformed else "true"


def _build_marker_command(marker_path: str) -> str:
    """Build the echo-to-marker-path command (bash-friendly path, single-quoted)."""
    return f"echo {_MARKER_CONTENT} > '{_bash_path(marker_path)}'"


def _build_injection_command(payload: str, marker_path: str) -> str | None:
    """Transform a payload into a marker-writing command.

    Replaces the attacker's command (everything after the injection vector)
    with ``echo MARKER > marker_path``. Returns None if no vector is found.

    For substitution vectors ($() and `` ` ``), the command INSIDE the
    substitution is replaced so the marker-write is evaluated inline.
    """
    mc = _build_marker_command(marker_path)
    for pat, vtype in _VECTORS:
        m = pat.search(payload)
        if m:
            prefix = payload[:m.start()]
            sep = m.group()
            if vtype == "substitution_dollar":
                rest = payload[m.end():]
                close = rest.find(")")
                suffix = rest[close + 1:] if close != -1 else ""
                return f"{prefix}$({mc}){suffix}"
            elif vtype == "substitution_backtick":
                rest = payload[m.end():]
                close = rest.find("`")
                suffix = rest[close + 1:] if close != -1 else ""
                return f"{prefix}`{mc}`{suffix}"
            else:
                return f"{prefix}{sep}{mc}"
    return None


def _build_vulnerable_command(ctx: ContextSpec, filtered: str, marker_path: str) -> str:
    """Build the vulnerable command for the given location.

    For argument/value locations, the payload must contain a separator to
    break out; the base command (``true``/``false``) is chosen so conditional
    operators work.

    For ``shell_command`` (input IS the command), a payload with a separator
    gets the base prepended (to avoid leading-separator syntax errors); a
    plain command gets a marker-write appended via ``&&``.
    """
    inj = _build_injection_command(filtered, marker_path)
    mc = _build_marker_command(marker_path)

    if ctx.location == "shell_command":
        if inj is not None:
            base = _select_base(inj)
            stripped = inj.lstrip()
            if stripped and stripped[0] in ";|&":
                return f"{base} {inj}"
            return inj
        # No separator — the payload itself is the command.
        return f"{filtered} && {mc}"

    # shell_arg, filename_arg, variable_value: need a separator to break out.
    if inj is None:
        return f"true {filtered}"  # no vector → won't create marker (benign)
    base = _select_base(inj)

    if ctx.location == "variable_value":
        # Real vuln: the variable is used UNQUOTED in a command, so metacharacters
        # in the value are interpreted during expansion. We set the variable and
        # eval it unquoted so separators break out. The base command is prepended
        # so conditional operators (&&/||) resolve correctly.
        return f'INPUT=\'{inj}\'; eval {base} "$INPUT"'
    # shell_arg / filename_arg
    return f"{base} {inj}"


class OracleSession:
    """Context manager keeping a temp dir for batch marker-file checks."""

    def __init__(self):
        self._tmpdir: str | None = None
        self._bash: str | None = None

    def __enter__(self) -> Self:
        self._tmpdir = tempfile.mkdtemp(prefix="cmdi_oracle_")
        self._bash = _find_bash()
        return self

    def __exit__(self, *args):
        if self._tmpdir and os.path.isdir(self._tmpdir):
            shutil.rmtree(self._tmpdir, ignore_errors=True)
            self._tmpdir = None
        return False

    def _run_bash(self, command: str, marker_path: str) -> bool:
        """Run a command via bash -c and check if the marker file appears."""
        if not self._bash:
            return False
        if os.path.exists(marker_path):
            os.remove(marker_path)
        try:
            subprocess.run(
                [self._bash, "-c", command],
                capture_output=True,
                timeout=5,
                stdin=subprocess.DEVNULL,
            )
        except Exception:
            pass
        return os.path.exists(marker_path)

    def check_fires(self, ctx: ContextSpec, payload: str) -> bool:
        """Return True if the payload causes command execution (marker file created)."""
        if not can_fire(payload, ctx.location):
            return False

        filtered = simulate_reflection(ctx, payload)
        if not filtered:
            return False  # blocked by filters

        if self._tmpdir is None:
            # Standalone use without context manager — delegate to ephemeral session.
            with OracleSession() as inner:
                return inner.check_fires(ctx, payload)

        marker_path = os.path.join(self._tmpdir, "marker.txt")
        command = _build_vulnerable_command(ctx, filtered, marker_path)
        return self._run_bash(command, marker_path)


def check_fires(ctx: ContextSpec, payload: str) -> bool:
    """Standalone check_fires — creates an ephemeral OracleSession per call."""
    with OracleSession() as session:
        return session.check_fires(ctx, payload)
