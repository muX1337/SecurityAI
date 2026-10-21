"""Static 'can this payload plausibly trigger XXE?' heuristic.

Determines whether a payload is a valid/effective XXE vector by checking its
XML structure. A payload "fires" if it is well-formed enough AND contains an
entity definition referencing external content (classic XXE), or a parameter
entity-based OOB pattern, or a billion-laughs expansion attack.
"""
from __future__ import annotations

import re

# An entity declaration (general or parameter).
_ENTITY_DECL_RE = re.compile(r"<!ENTITY", re.IGNORECASE)
_SYSTEM_RE = re.compile(r"\bSYSTEM\b", re.IGNORECASE)
_PUBLIC_RE = re.compile(r"\bPUBLIC\b", re.IGNORECASE)
_PARAM_ENTITY_RE = re.compile(r"<!ENTITY\s*%")
_ENTITY_REF_RE = re.compile(r"&[a-zA-Z_][a-zA-Z0-9_.-]*;")
_PARAM_REF_RE = re.compile(r"%[a-zA-Z_][a-zA-Z0-9_.-]*;")
_DOCTYPE_RE = re.compile(r"<!DOCTYPE", re.IGNORECASE)


def _is_well_formed_enough(payload: str) -> bool:
    """Quick structural sanity: balanced enough to be parseable.

    We don't require a full XML parse (the payload may be a fragment meant to be
    injected into a template). We just reject obviously broken input: empty,
    unbalanced angle brackets, or missing entity declaration syntax.
    """
    if not payload or not payload.strip():
        return False
    s = payload.strip()
    # Must have some XML-like structure.
    if "<" not in s and "&" not in s:
        return False
    # Grossly unbalanced brackets → broken — unless it's the common case of
    # a DOCTYPE line without a closing root (a valid injection fragment).
    return not (s.count("<") != s.count(">") and "SYSTEM" not in s.upper()
                and not _DOCTYPE_RE.search(s))


def can_fire(payload: str, location: str = "xml_body") -> bool:
    """Return True if the payload plausibly triggers an XXE when parsed.

    A payload fires if ANY of:
      1. Classic XXE: ENTITY + SYSTEM/PUBLIC (external entity reads a file/URL).
      2. Parameter entity OOB: parameter entity (%) + ENTITY declaration.
      3. Billion laughs: nested ENTITY declarations with entity references.
      4. SVG/SOAP wrappers containing an ENTITY + SYSTEM.

    Plain valid XML with no entity declarations does NOT fire (it is benign).
    """
    if not payload or not payload.strip():
        return False
    s = payload.strip()

    if not _is_well_formed_enough(s):
        return False

    has_entity = bool(_ENTITY_DECL_RE.search(s))
    has_system = bool(_SYSTEM_RE.search(s) or _PUBLIC_RE.search(s))
    has_param = bool(_PARAM_ENTITY_RE.search(s))
    has_ref = bool(_ENTITY_REF_RE.search(s))

    # Classic external entity: <!ENTITY xxe SYSTEM "...">
    if has_entity and has_system:
        return True

    # Parameter entity OOB: <!ENTITY % dtd SYSTEM "...">
    if has_entity and has_param:
        return True

    # Billion laughs: multiple ENTITY declarations referencing each other
    return bool(has_entity and has_ref and s.count("<!ENTITY") >= 2)
