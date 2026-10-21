"""SSTI oracle: check_fires(ctx, payload) -> bool.

The oracle is a simple, dependency-free simulated template renderer. It models
whether a payload would be EVALUATED by the target engine after the context's
filters are applied. Success = a template expression was evaluated and either:
  - a math expression produced a changed value (e.g. {{7*7}} -> 49), or
  - a known data-exfiltration / RCE marker structure is present and intact.

This is fast and deterministic — no HTTP listener, no real subprocess. We avoid
executing real RCE payloads; we only confirm the expression would be evaluated
(i.e. that the filter did not neutralize it and the engine syntax matches).
"""
from __future__ import annotations

import re
from typing import Any, Self

from ..can_fire import can_fire
from ..context import ContextSpec, engine_delimiters, simulate_reflection

# A restricted eval namespace: only safe arithmetic/typing primitives. Real
# SSTI payloads that buildins() / __class__ would need are never actually
# executed; we only evaluate benign math probes to confirm the engine parses
# and computes the expression.
_SAFE_EVAL_GLOBALS: dict[str, Any] = {"__builtins__": {}}
_SAFE_EVAL_LOCALS: dict[str, Any] = {
    "int": int, "float": float, "str": str, "len": len, "range": range,
}


def _safe_math_eval(expr: str) -> str | None:
    """Evaluate a pure-arithmetic expression safely; return str(result) or None.

    Only allows a narrow charset (digits, operators, parens, quotes, spaces,
    and the names in _SAFE_EVAL_LOCALS). Rejects anything containing
    underscores, dots, brackets, or letters outside the allowlist so that
    attribute walks / dunders can never execute here.
    """
    if not expr or not expr.strip():
        return None
    # Allow only digits, basic operators, parens, quotes, whitespace, and a
    # handful of safe builtin names.
    allowed_names = {"int", "float", "str", "len", "range"}
    token_check = re.sub(r"[0-9+\-*/%().,'\" \t]", "", expr)
    # token_check now contains only letters/underscores/etc that must all be
    # in allowed_names.
    words = re.findall(r"[A-Za-z_]+", token_check)
    for w in words:
        if w not in allowed_names:
            return None
    # Hard reject any attribute access / dunder — never executed.
    if "_" in expr or "." in expr or "[" in expr:
        return None
    try:
        result = eval(expr, dict(_SAFE_EVAL_GLOBALS), dict(_SAFE_EVAL_LOCALS))
    except Exception:
        return None
    return str(result)


def _extract_jinja_exprs(payload: str, open_d: str, close_d: str) -> list[str]:
    """Extract expression bodies between open_d and close_d (e.g. {{ ... }})."""
    exprs: list[str] = []
    idx = 0
    while True:
        start = payload.find(open_d, idx)
        if start == -1:
            break
        end = payload.find(close_d, start + len(open_d))
        if end == -1:
            break
        exprs.append(payload[start + len(open_d):end].strip())
        idx = end + len(close_d)
    return exprs


def _has_data_marker(payload: str) -> bool:
    """Structural check: does the payload carry a data-exfil / RCE structure
    that, if the expression is evaluated, would leak data or execute?

    We do NOT execute these; we confirm the marker survived the filters and the
    expression delimiters are intact (so the engine would evaluate it).
    """
    markers = (
        "config", "request", "self",
        "__class__", "__mro__", "__subclasses__", "__globals__", "__builtins__",
        "__init__", "__bases__",
        "lipsum", "cycler", "joiner", "namespace",
        "get_flashed_messages", "dict.__init__",
        "popen", "system", "Runtime", "exec", "IOUtils",
        "Execute", "class.inspect", "import",
    )
    return any(m in payload for m in markers)


def _would_evaluate(payload: str, location: str) -> bool:
    """Decide whether the engine at `location` would evaluate `payload`'s
    expression(s). Returns True on either:
      - a math expression that evaluates to a changed value, or
      - an intact data/RCE marker inside expression delimiters.
    """
    delims = engine_delimiters(location)

    # Jinja2/Twig: {{ ... }} expressions
    if "{{" in delims and "}}" in delims:
        exprs = _extract_jinja_exprs(payload, "{{", "}}")
        for expr in exprs:
            if not expr:
                continue
            # Math probe: does it evaluate to something other than itself?
            res = _safe_math_eval(expr)
            if res is not None and res != expr:
                return True
            # Non-math expression carrying a data marker: the engine would
            # evaluate it (we just confirm the marker is intact).
            if _has_data_marker(expr):
                return True
        # {% statement %} blocks: if they survived filters, the engine runs them.
        if "{%" in delims and ("%}" in delims):
            stmts = _extract_jinja_exprs(payload, "{%", "%}")
            for stmt in stmts:
                if stmt.strip():
                    return True
        return False

    # FreeMarker / Mako: ${ ... }
    if "${" in delims:
        exprs = _extract_jinja_exprs(payload, "${", "}")
        for expr in exprs:
            if not expr:
                continue
            res = _safe_math_eval(expr)
            if res is not None and res != expr:
                return True
            if _has_data_marker(expr):
                return True
        return False

    # Velocity: $... (presence of a velocity statement/set is enough)
    if "$" in delims:
        if "$" in payload and _has_data_marker(payload):
            return True
        # Velocity math isn't expressed the same way; a set statement counts.
        return "#set" in payload

    # Fallback: ERB/JS/Thymeleaf generic syntaxes.
    for opener, closer in (("<%", "%>"), ("#{", "}"), ("*{", "}")):
        if opener in payload:
            exprs = _extract_jinja_exprs(payload, opener, closer)
            for expr in exprs:
                res = _safe_math_eval(expr)
                if res is not None and res != expr:
                    return True
                if _has_data_marker(expr):
                    return True
    return False


class OracleSession:
    """Compatibility shim mirroring the SSRF OracleSession API.

    The SSTI oracle is stateless (no listener), but we keep the same shape so
    the eval harness and scripts transfer cleanly.
    """

    def __init__(self, listener_port: int = 0):
        self.listener_port = listener_port

    def __enter__(self) -> Self:
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def check_fires(self, ctx: ContextSpec, payload: str) -> bool:
        """Return True if the payload triggers an evaluated template expression
        at the context's location after filters are applied."""
        if not can_fire(payload, ctx.location):
            return False
        filtered = simulate_reflection(ctx, payload)
        if not filtered:
            return False
        return _would_evaluate(filtered, ctx.location)


def check_fires(ctx: ContextSpec, payload: str) -> bool:
    """Standalone check_fires — stateless for SSTI."""
    with OracleSession() as session:
        return session.check_fires(ctx, payload)
