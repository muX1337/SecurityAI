"""CRLF oracle: check_fires(ctx, payload) -> bool.

Ground truth for whether a payload triggers an HTTP response injection. Unlike
the SSRF oracle (which uses a network callback listener), the CRLF oracle is a
pure-Python HTTP response construction simulator:

  1. Apply the context's filters to the payload (decode -> block).
  2. Build a simulated HTTP response with the (filtered) payload injected into
     the header slot for the context's location.
  3. Parse the response by splitting header lines on newline (lenient: a bare
     linefeed \\n OR a CR+LF both terminate a header line, matching real HTTP
     parsers) and check whether the payload introduced extra header lines or
     injected-header keywords beyond the benign baseline.

A "fire" means the injected content broke out of its header value and added a
new header line or body content — i.e. a real CRLF / response-splitting
injection.
"""
from __future__ import annotations

from typing import Self

from ..context import ContextSpec, location_header_name, simulate_reflection

# Header keywords whose presence on an injected line indicates a successful
# header injection (case-insensitive substring).
_INJECTED_KEYWORDS = (
    "set-cookie", "content-length", "location:", "content-type:",
    "x-injected:", "x-forwarded-for:", "host:",
)


def _build_response(ctx: ContextSpec, reflected: str) -> str:
    """Construct the simulated HTTP response with `reflected` injected."""
    header_name = location_header_name(ctx)
    return (
        "HTTP/1.1 200 OK\r\n"
        f"{header_name}: {reflected}\r\n"
        "Content-Type: text/html\r\n"
        "\r\n"
        "<html>body</html>"
    )


def _split_header_block(response: str) -> list[str]:
    """Split the response into header lines, terminating at the blank line that
    ends the header block. Lenient line splitting: split on '\\n' and strip a
    trailing '\\r' from each line (so '\\r\\n', '\\n', and '\\r' all act as line
    separators, mirroring tolerant HTTP server parsers)."""
    # Normalize a bare CR (with no following LF) into CRLF so that split('\n')
    # catches CR-only splits too.
    normalized = response.replace("\r\n", "\n").replace("\r", "\n")
    lines = normalized.split("\n")
    out: list[str] = []
    for ln in lines:
        out.append(ln)
        if ln == "":
            break
    return out


def check_fires(ctx: ContextSpec, payload: str) -> bool:
    """Return True if the payload triggers an HTTP response injection.

    Deterministic, listener-free, fast.
    """
    # Web servers URL-decode query parameters before use. Simulate that here
    # so %0d%0a becomes actual \r\n.
    import urllib.parse
    decoded = urllib.parse.unquote(payload)

    reflected = simulate_reflection(ctx, decoded)
    if not reflected:
        return False  # a block filter rejected the payload

    response = _build_response(ctx, reflected)
    header_lines = _split_header_block(response)

    # Benign header block (no injection) = status + 1 injected header +
    # Content-Type + empty terminator = 4 lines. If the payload split the
    # injected value into extra lines, the count grows.
    benign_count = 4
    if len(header_lines) > benign_count:
        return True

    # Build a baseline response (empty payload) to compare against
    baseline_response = _build_response(ctx, "")
    baseline_lines = _split_header_block(baseline_response)

    # If the injected response has MORE header lines than baseline, injection added lines
    if len(header_lines) > len(baseline_lines):
        return True

    # Compare lines: if any line after the injected header differs from
    # the baseline, the injection modified the response
    header_name = location_header_name(ctx)
    original_prefix = f"{header_name}:"
    for i, (injected_ln, baseline_ln) in enumerate(zip(header_lines, baseline_lines)):
        if injected_ln.startswith(original_prefix):
            continue  # the injected header line itself is expected to differ
        if injected_ln != baseline_ln:
            return True  # a line was changed by the injection

    return False


class OracleSession:
    """Mirror of the SSRF OracleSession API for drop-in compatibility.

    The CRLF oracle needs no listener; the session is stateless and delegates
    to check_fires. Keeping the class lets scripts/03 and the eval harness use
    the same `with OracleSession() as s: s.check_fires(...)` shape.
    """

    def __init__(self, listener_port: int = 0):
        # listener_port accepted and ignored (no network listener for CRLF).
        self.listener_port = listener_port

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def check_fires(self, ctx: ContextSpec, payload: str) -> bool:
        return check_fires(ctx, payload)
