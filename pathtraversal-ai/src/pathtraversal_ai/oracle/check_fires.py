"""Path traversal / LFI oracle: check_fires(ctx, payload) -> bool.

Self-contained file-system oracle — pure Python stdlib, no subprocess or network.

Design (mirrors the spec):
  1. A temp directory is created with this layout:
       <tmpdir>/
         base/               <- the app's "file directory"
           safe_file.txt     <- a legitimate file inside base (no marker)
  2. The server URL-decodes the raw payload once (every web server does this).
  3. The context filters are applied to the decoded payload.
  4. The vulnerable code simulates: open(base_dir + "/" + filtered_payload).
  5. We resolve the path with os.path.normpath (so '../' escapes base) and
     try to read it.
  6. If the marker content appears in the result -> the traversal "fired".

Marker files are planted at EVERY ancestor directory level (so any number of
'../' segments lands on a target) and at known absolute-path targets
(etc/passwd, Windows/win.ini) rooted inside the sandbox.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
from typing import Self
from urllib.parse import unquote

from ..can_fire import can_fire
from ..context import ContextSpec, simulate_reflection

# Marker content written to every target file. If the oracle sees this in the
# read result, the traversal succeeded.
_MARKER = "PATH_TRAVERSAL_MARKER"

# Target filenames planted at every ancestor level. Any traversal payload that
# resolves to one of these (at any depth) reads the marker.
_TARGET_FILES = (
    "secret.txt",
    os.path.join("etc", "passwd"),
    os.path.join("etc", "shadow"),
    os.path.join("etc", "hosts"),
    os.path.join("Windows", "win.ini"),
    os.path.join("var", "log", "auth.log"),
    os.path.join("proc", "self", "environ"),
    os.path.join("proc", "version"),
)


def _plant_markers(tmpdir: str, base_dir: str) -> None:
    """Create the sandbox layout and plant marker files at every escape level.

    For each ancestor of tmpdir (0..5 levels up), plant every target file
    containing the marker. This ensures a traversal payload with ANY number of
    '../' segments lands on a readable marker.
    """
    os.makedirs(base_dir, exist_ok=True)
    with open(os.path.join(base_dir, "safe_file.txt"), "w", encoding="utf-8") as f:
        f.write("this is a safe file\n")  # legitimate, NO marker

    for n_up in range(6):
        ancestor = tmpdir
        for _ in range(n_up):
            ancestor = os.path.dirname(ancestor)
        for target in _TARGET_FILES:
            full = os.path.join(ancestor, target)
            try:
                os.makedirs(os.path.dirname(full), exist_ok=True)
                with open(full, "w", encoding="utf-8") as f:
                    f.write(_MARKER + "\n")
            except OSError:
                pass  # ancestor may be unwritable (e.g. root); skip silently

    # Portable fallback: the same markers rooted INSIDE the sandbox. A relative
    # payload that escapes base/ resolves to a path like /secret.txt on Linux or
    # C:\\secret.txt on Windows; neither is writable, so the read is re-rooted
    # into the sandbox (see _confine) where these markers live. This keeps the
    # oracle's answer identical on every platform.
    for target in _TARGET_FILES:
        full = os.path.join(tmpdir, target)
        try:
            os.makedirs(os.path.dirname(full), exist_ok=True)
            with open(full, "w", encoding="utf-8") as f:
                f.write(_MARKER + "\n")
        except OSError:
            pass


def _wrapper_fires(filtered: str) -> bool:
    """Return True if a PHP/stream wrapper payload plausibly reads a target.

    php://, file://, data:// (and zip/phar/expect) are LFI primitives — the
    vulnerable include/read would evaluate the scheme, so any well-formed
    wrapper counts as a fire.
    """
    lower = filtered.strip().lower()
    if lower.startswith("php://"):
        return True
    if lower.startswith("file://"):
        return True
    if lower.startswith("data://"):
        return True
    return bool(lower.startswith(("zip://", "phar://", "expect://", "input://")))


def _resolve(base_dir: str, filtered: str, sandbox_root: str) -> str:
    """Build the vulnerable path the application would open.

    For wrapper payloads the scheme takes over (handled separately). For
    relative payloads, concatenate base_dir + '/' + payload and normalize so
    '../' segments collapse. For absolute payloads, the sandbox confines them:
    a Unix-absolute path like '/etc/passwd' is rooted at sandbox_root.
    """
    stripped = filtered.strip()
    if "://" in stripped:
        return stripped
    if stripped.startswith("/"):
        return os.path.normpath(os.path.join(sandbox_root, stripped.lstrip("/")))
    if re.match(r"^[a-zA-Z]:[\\/]", stripped):
        no_drive = re.sub(r"^[a-zA-Z]:[\\/]", "", stripped)
        return os.path.normpath(os.path.join(sandbox_root, no_drive))
    combined = os.path.normpath(os.path.join(base_dir, stripped))
    root = os.path.normpath(sandbox_root)
    if combined == root or combined.startswith(root + os.sep):
        return combined
    # The payload escaped base/. Do not read the real filesystem from a test
    # oracle: re-root the escaped tail (../../../etc/passwd -> etc/passwd) at the
    # sandbox, where the marker files live. Same semantics, every platform.
    parts = [p for p in re.split(r"[\\/]+", stripped) if p not in ("", ".", "..")]
    if not parts:
        return root
    return os.path.normpath(os.path.join(root, *parts))


class OracleSession:
    """Context manager keeping a sandbox temp dir for batch file-path checks."""

    def __init__(self):
        self._tmpdir: str | None = None

    def __enter__(self) -> Self:
        self._tmpdir = tempfile.mkdtemp(prefix="pathtrav_oracle_")
        return self

    def __exit__(self, *args):
        if self._tmpdir and os.path.isdir(self._tmpdir):
            shutil.rmtree(self._tmpdir, ignore_errors=True)
            self._tmpdir = None
        return False

    def check_fires(self, ctx: ContextSpec, payload: str) -> bool:
        """Return True if the payload reads a marker file."""
        if not can_fire(payload, ctx.location):
            return False

        # Step 1: web server URL-decodes the raw input (always happens).
        server_decoded = unquote(payload)

        # Step 2: apply context filters on the decoded input.
        filtered = simulate_reflection(ctx, server_decoded)
        if not filtered:
            return False  # blocked by filters

        if self._tmpdir is None:
            with OracleSession() as inner:
                return inner.check_fires(ctx, payload)

        base_dir = os.path.join(self._tmpdir, "base")
        _plant_markers(self._tmpdir, base_dir)

        # Wrapper payloads (php://, file://, data://) — primitive-level fire.
        if _wrapper_fires(filtered):
            return True

        resolved = _resolve(base_dir, filtered, self._tmpdir)

        # Read the resolved file and check for the marker.
        try:
            with open(resolved, encoding="utf-8", errors="ignore") as fh:
                content = fh.read()
        except OSError:
            return False
        return _MARKER in content


def check_fires(ctx: ContextSpec, payload: str) -> bool:
    """Standalone check_fires — creates an ephemeral OracleSession per call."""
    with OracleSession() as session:
        return session.check_fires(ctx, payload)
