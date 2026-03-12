"""
Fray Vulnerability Verification & Proof Module.

Verifies exploitability and generates proof artifacts:
  - SQLi: dump actual data (version, databases, tables)
  - XSS: headless browser alert verification + screenshot
  - SSRF: cloud metadata extraction proof
  - RCE: command output capture
  - File read: content extraction

Generates:
  - JSON proof report
  - Screenshot (if headless browser available)
  - Data dump (extracted records)

Usage:
    verifier = VulnVerifier()
    proof = verifier.verify_sqli(url, param, technique, payload)
    proof = verifier.verify_xss(url, param, payload)
    proof = verifier.verify_ssrf(url, param, payload)

Zero external dependencies (screenshots require Playwright).
"""

import json
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional


class Proof:
    """Verification proof artifact."""
    def __init__(self, vuln_type: str, url: str, param: str):
        self.vuln_type = vuln_type
        self.url = url
        self.param = param
        self.verified = False
        self.severity = "unknown"
        self.evidence: Dict[str, Any] = {}
        self.extracted_data: List[Dict[str, str]] = []
        self.screenshot_path: Optional[str] = None
        self.timestamp = datetime.now().isoformat()
        self.requests_made = 0
        self.duration_ms = 0

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "vuln_type": self.vuln_type,
            "url": self.url,
            "param": self.param,
            "verified": self.verified,
            "severity": self.severity,
            "evidence": self.evidence,
            "timestamp": self.timestamp,
            "requests_made": self.requests_made,
            "duration_ms": self.duration_ms,
        }
        if self.extracted_data:
            d["extracted_data"] = self.extracted_data[:50]
        if self.screenshot_path:
            d["screenshot"] = self.screenshot_path
        return d

    def save(self, path: str = "") -> str:
        """Save proof to JSON file."""
        if not path:
            path = f"/tmp/fray_proof_{self.vuln_type}_{int(time.time())}.json"
        Path(path).write_text(json.dumps(self.to_dict(), indent=2, ensure_ascii=False))
        return path


class VulnVerifier:
    """Verify vulnerabilities and generate exploitation proof."""

    def __init__(self, timeout: int = 10, verify_ssl: bool = True):
        self.timeout = timeout
        self.verify_ssl = verify_ssl

    def verify_sqli(self, url: str, param: str,
                    payload: str = "", cookie: str = "") -> Proof:
        """Verify SQL injection by extracting real data."""
        from fray.sqli import SQLiInjector
        proof = Proof("sqli", url, param)
        t0 = time.monotonic()

        injector = SQLiInjector(url, param, cookie=cookie,
                                timeout=self.timeout,
                                verify_ssl=self.verify_ssl, level=2, risk=2)
        result = injector.test_all()

        if result.vulnerable:
            proof.verified = True
            proof.severity = "critical"
            proof.evidence = {
                "dbms": result.dbms,
                "techniques": [f.technique for f in result.findings],
                "findings_count": len(result.findings),
            }

            # Try to extract actual data as proof
            version = injector.extract_data("SELECT version()")
            if version:
                proof.evidence["db_version"] = version
                proof.extracted_data.append({"type": "version", "value": version})

            user = injector.extract_data("SELECT user()")
            if user:
                proof.evidence["db_user"] = user
                proof.extracted_data.append({"type": "user", "value": user})

            dbs = injector.enumerate_databases()
            if dbs:
                proof.evidence["databases"] = dbs
                for db in dbs[:10]:
                    proof.extracted_data.append({"type": "database", "value": db})

        proof.requests_made = result.requests_made
        proof.duration_ms = int((time.monotonic() - t0) * 1000)
        return proof

    def verify_xss(self, url: str, param: str,
                   payload: str = "", cookie: str = "") -> Proof:
        """Verify XSS via headless browser (alert dialog detection + screenshot)."""
        proof = Proof("xss", url, param)
        t0 = time.monotonic()

        # Phase 1: Reflection check via scanner
        from fray.xss import XSSScanner
        scanner = XSSScanner(url, param, cookie=cookie,
                             timeout=self.timeout,
                             verify_ssl=self.verify_ssl)
        result = scanner.scan()

        if result.vulnerable:
            proof.verified = True
            proof.severity = "high"
            proof.evidence = {
                "contexts": result.contexts_found,
                "filters": result.filters_detected,
                "findings_count": len(result.findings),
                "dom_sources": result.dom_sources[:5],
                "dom_sinks": result.dom_sinks[:5],
            }
            for f in result.findings:
                proof.extracted_data.append({
                    "type": "xss_payload",
                    "context": f.context,
                    "payload": f.payload,
                    "confidence": f.confidence,
                })

        # Phase 2: Headless browser verification (if available)
        try:
            from fray.headless import HeadlessEngine
            engine = HeadlessEngine()
            if engine._use_playwright:
                best_payload = payload
                if not best_payload and result.findings:
                    best_payload = result.findings[0].payload

                if best_payload:
                    xss_result = engine.verify_xss(url, best_payload, param)
                    if xss_result["verified"]:
                        proof.verified = True
                        proof.severity = "critical"  # Upgrade: browser-verified
                        proof.evidence["browser_verified"] = True
                        proof.evidence["alert_message"] = xss_result.get("evidence", "")
                        proof.screenshot_path = xss_result.get("screenshot")
                engine.close()
        except ImportError:
            proof.evidence["browser_verification"] = "skipped (playwright not installed)"

        proof.requests_made = result.requests_made
        proof.duration_ms = int((time.monotonic() - t0) * 1000)
        return proof

    def verify_ssrf(self, url: str, param: str, cookie: str = "") -> Proof:
        """Verify SSRF by extracting cloud metadata."""
        from fray.ssrf import SSRFScanner
        proof = Proof("ssrf", url, param)
        t0 = time.monotonic()

        scanner = SSRFScanner(url, param, cookie=cookie,
                              timeout=self.timeout,
                              verify_ssl=self.verify_ssl, level=2)
        result = scanner.scan()

        if result.vulnerable:
            proof.verified = True
            proof.severity = "critical"
            proof.evidence = {
                "findings_count": len(result.findings),
                "cloud_providers": list(set(f.cloud_provider for f in result.findings if f.cloud_provider)),
                "techniques": list(set(f.technique for f in result.findings)),
            }
            for f in result.findings:
                proof.extracted_data.append({
                    "type": f.technique,
                    "target": f.target_type,
                    "payload": f.payload,
                    "evidence": f.evidence,
                })

        proof.requests_made = result.requests_made
        proof.duration_ms = int((time.monotonic() - t0) * 1000)
        return proof

    def verify_deser(self, url: str, param: str, cookie: str = "") -> Proof:
        """Verify insecure deserialization."""
        from fray.deser import DeserScanner
        proof = Proof("deserialization", url, param)
        t0 = time.monotonic()

        scanner = DeserScanner(url, param, cookie=cookie,
                               timeout=self.timeout,
                               verify_ssl=self.verify_ssl, level=2)
        result = scanner.scan()

        if result.vulnerable:
            proof.verified = True
            proof.severity = "critical"
            proof.evidence = {
                "detected_tech": result.detected_tech,
                "findings_count": len(result.findings),
                "languages": list(set(f.language for f in result.findings)),
            }
            for f in result.findings:
                proof.extracted_data.append({
                    "type": f.name,
                    "language": f.language,
                    "evidence": f.evidence,
                })

        proof.requests_made = result.requests_made
        proof.duration_ms = int((time.monotonic() - t0) * 1000)
        return proof

    def generate_report(self, proofs: List[Proof], output_path: str = "") -> str:
        """Generate a combined proof report from multiple verifications."""
        report = {
            "generated_at": datetime.now().isoformat(),
            "total_verified": sum(1 for p in proofs if p.verified),
            "total_tested": len(proofs),
            "proofs": [p.to_dict() for p in proofs],
        }
        path = output_path or f"/tmp/fray_proof_report_{int(time.time())}.json"
        Path(path).write_text(json.dumps(report, indent=2, ensure_ascii=False))
        return path
