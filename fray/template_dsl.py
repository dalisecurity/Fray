#!/usr/bin/env python3
"""
YAML Template DSL (#154) — Nuclei-like custom security checks.

Define HTTP-based security checks in YAML files and run them against targets.
Templates support variables, matchers, extractors, and conditional logic.

Template format:

    id: cve-2024-1234
    info:
      name: Example CVE Check
      author: security-team
      severity: high
      description: Checks for CVE-2024-1234 via path traversal.
      tags:
        - cve
        - lfi
      reference:
        - https://nvd.nist.gov/vuln/detail/CVE-2024-1234

    http:
      - method: GET
        path:
          - "{{BaseURL}}/..%2f..%2fetc/passwd"
          - "{{BaseURL}}/api/v1/files?path=../../etc/passwd"
        headers:
          User-Agent: "Mozilla/5.0"
        matchers-condition: or
        matchers:
          - type: word
            words:
              - "root:x:0:0"
            part: body
          - type: status
            status:
              - 200
          - type: regex
            regex:
              - "root:[x*]:0:0"
            part: body

        extractors:
          - type: regex
            regex:
              - "(root:[^:]+:[0-9]+:[0-9]+)"
            group: 1
            part: body

    # Multi-step requests (e.g., CSRF token extraction then exploit)
    http:
      - method: GET
        path:
          - "{{BaseURL}}/login"
        extractors:
          - type: regex
            name: csrf_token
            regex:
              - 'name="csrf_token" value="([^"]+)"'
            group: 1
            internal: true

      - method: POST
        path:
          - "{{BaseURL}}/admin/delete"
        body: "csrf_token={{csrf_token}}&id=1"
        matchers:
          - type: status
            status:
              - 200
              - 302

Usage:
    from fray.template_dsl import load_templates, run_templates

    templates = load_templates("~/.fray/templates/")
    results = run_templates(templates, "https://target.com")

CLI:
    fray template run ./my-checks/ -t https://target.com
    fray template list
    fray template validate ./check.yaml
"""

from __future__ import annotations

import glob
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ── YAML loading — prefer PyYAML, fallback to basic parser ───────────────

_HAS_YAML = False
try:
    import yaml
    _HAS_YAML = True
except ImportError:
    yaml = None  # type: ignore


def _basic_yaml_load(text: str) -> dict:
    """Minimal YAML-like parser for simple templates when PyYAML is absent.

    Handles flat key-value, lists, and one level of nesting. NOT a full parser.
    """
    result: dict = {}
    current_key = None
    current_list: Optional[list] = None
    indent_stack: list = []

    for line in text.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        indent = len(line) - len(line.lstrip())

        # List item
        if stripped.startswith("- "):
            val = stripped[2:].strip().strip('"').strip("'")
            if current_list is not None:
                current_list.append(val)
            continue

        # Key-value
        if ":" in stripped:
            key, _, val = stripped.partition(":")
            key = key.strip()
            val = val.strip().strip('"').strip("'")

            if val:
                result[key] = val
                current_key = None
                current_list = None
            else:
                # Start of a nested section or list
                result[key] = []
                current_key = key
                current_list = result[key]

    return result


def _load_yaml(text: str) -> Any:
    """Load YAML from text, using PyYAML if available."""
    if _HAS_YAML:
        return yaml.safe_load(text)
    return _basic_yaml_load(text)


# ── Template data structures ─────────────────────────────────────────────

class TemplateInfo:
    """Metadata about a template."""
    __slots__ = ("id", "name", "author", "severity", "description",
                 "tags", "references", "file_path")

    def __init__(self, data: dict, file_path: str = ""):
        info = data.get("info", {}) or {}
        self.id = data.get("id", "unknown")
        self.name = info.get("name", self.id)
        self.author = info.get("author", "")
        self.severity = info.get("severity", "info").lower()
        self.description = info.get("description", "")
        self.tags = info.get("tags", []) or []
        self.references = info.get("reference", []) or []
        self.file_path = file_path


class Matcher:
    """A single matcher condition."""
    __slots__ = ("type", "words", "regex_patterns", "status_codes",
                 "part", "negative", "condition")

    def __init__(self, data: dict):
        self.type = data.get("type", "word")
        self.words = data.get("words", []) or []
        self.regex_patterns = [re.compile(r) for r in (data.get("regex", []) or [])]
        self.status_codes = data.get("status", []) or []
        self.part = data.get("part", "body")
        self.negative = data.get("negative", False)
        self.condition = data.get("condition", "or")

    def evaluate(self, status: int, headers: dict, body: str) -> bool:
        """Check if this matcher matches the response."""
        target = body
        if self.part == "header":
            target = "\n".join(f"{k}: {v}" for k, v in headers.items())
        elif self.part == "all":
            target = "\n".join(f"{k}: {v}" for k, v in headers.items()) + "\n" + body

        result = False
        if self.type == "word":
            if self.condition == "and":
                result = all(w in target for w in self.words)
            else:
                result = any(w in target for w in self.words)
        elif self.type == "regex":
            if self.condition == "and":
                result = all(p.search(target) for p in self.regex_patterns)
            else:
                result = any(p.search(target) for p in self.regex_patterns)
        elif self.type == "status":
            result = status in self.status_codes
        elif self.type == "size":
            # size matcher: check body length
            sizes = [int(s) for s in (self.words or []) if str(s).isdigit()]
            result = len(body) in sizes if sizes else False

        return (not result) if self.negative else result


class Extractor:
    """Extract values from responses for use in subsequent requests."""
    __slots__ = ("type", "name", "regex_patterns", "group",
                 "part", "internal")

    def __init__(self, data: dict):
        self.type = data.get("type", "regex")
        self.name = data.get("name", "")
        self.regex_patterns = [re.compile(r) for r in (data.get("regex", []) or [])]
        self.group = data.get("group", 0)
        self.part = data.get("part", "body")
        self.internal = data.get("internal", False)

    def extract(self, status: int, headers: dict, body: str) -> List[str]:
        """Extract values from response."""
        target = body
        if self.part == "header":
            target = "\n".join(f"{k}: {v}" for k, v in headers.items())

        results = []
        if self.type == "regex":
            for pattern in self.regex_patterns:
                for m in pattern.finditer(target):
                    try:
                        results.append(m.group(self.group))
                    except IndexError:
                        results.append(m.group(0))
        elif self.type == "kval":
            # Key-value extraction from headers
            for key in (self.regex_patterns or []):
                if hasattr(key, 'pattern'):
                    key = key.pattern
                val = headers.get(key, headers.get(key.lower(), ""))
                if val:
                    results.append(val)
        return results


class HTTPRequest:
    """A single HTTP request step in a template."""
    __slots__ = ("method", "paths", "headers", "body",
                 "matchers", "matchers_condition", "extractors",
                 "redirects", "max_redirects")

    def __init__(self, data: dict):
        self.method = (data.get("method", "GET") or "GET").upper()
        self.paths = data.get("path", []) or []
        if isinstance(self.paths, str):
            self.paths = [self.paths]
        self.headers = data.get("headers", {}) or {}
        self.body = data.get("body", "")
        self.matchers_condition = data.get("matchers-condition", "or")
        self.matchers = [Matcher(m) for m in (data.get("matchers", []) or [])]
        self.extractors = [Extractor(e) for e in (data.get("extractors", []) or [])]
        self.redirects = data.get("redirects", True)
        self.max_redirects = data.get("max-redirects", 3)


class Template:
    """A complete YAML template with info + HTTP request steps."""

    def __init__(self, data: dict, file_path: str = ""):
        self.info = TemplateInfo(data, file_path)
        self.requests: List[HTTPRequest] = []
        self.raw_data = data
        self.file_path = file_path

        http_section = data.get("http", []) or []
        if isinstance(http_section, dict):
            http_section = [http_section]
        for step in http_section:
            if isinstance(step, dict):
                self.requests.append(HTTPRequest(step))


# ── Template loading ─────────────────────────────────────────────────────

def load_template(path: str) -> Optional[Template]:
    """Load a single YAML template file."""
    try:
        text = Path(path).read_text(encoding="utf-8")
        data = _load_yaml(text)
        if not isinstance(data, dict):
            return None
        if "id" not in data and "info" not in data:
            return None
        return Template(data, file_path=path)
    except Exception as e:
        sys.stderr.write(f"  [template] Error loading {path}: {e}\n")
        return None


def load_templates(path: str) -> List[Template]:
    """Load templates from a file or directory.

    Supports:
        - Single .yaml/.yml file
        - Directory (recursive glob for *.yaml, *.yml)
        - Glob pattern (e.g., "checks/*.yaml")
    """
    p = Path(path).expanduser()
    templates: List[Template] = []

    if p.is_file():
        t = load_template(str(p))
        if t:
            templates.append(t)
    elif p.is_dir():
        for ext in ("*.yaml", "*.yml"):
            for f in sorted(p.rglob(ext)):
                t = load_template(str(f))
                if t:
                    templates.append(t)
    else:
        # Try as glob
        for f in sorted(glob.glob(str(p), recursive=True)):
            if f.endswith((".yaml", ".yml")):
                t = load_template(f)
                if t:
                    templates.append(t)

    return templates


def load_builtin_templates() -> List[Template]:
    """Load built-in templates from ~/.fray/templates/."""
    tpl_dir = Path.home() / ".fray" / "templates"
    if tpl_dir.exists():
        return load_templates(str(tpl_dir))
    return []


# ── Variable interpolation ───────────────────────────────────────────────

def _interpolate(text: str, variables: dict) -> str:
    """Replace {{VarName}} placeholders with variable values."""
    if not text or "{{" not in text:
        return text
    for key, val in variables.items():
        text = text.replace("{{" + key + "}}", str(val))
    return text


# ── HTTP execution ───────────────────────────────────────────────────────

def _send_request(method: str, url: str, headers: dict,
                  body: Optional[str], verify: bool = False,
                  timeout: int = 10) -> Tuple[int, dict, str, float]:
    """Send an HTTP request using stdlib. Returns (status, headers, body, ms)."""
    t0 = time.monotonic()

    data_bytes = body.encode("utf-8") if body else None
    req = urllib.request.Request(url, data=data_bytes, headers=headers,
                                method=method)

    ctx = None
    if url.startswith("https"):
        ctx = ssl.create_default_context()
        if not verify:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        resp_body = resp.read().decode("utf-8", errors="replace")
        elapsed = (time.monotonic() - t0) * 1000
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        return resp.status, resp_headers, resp_body, elapsed
    except urllib.error.HTTPError as e:
        resp_body = (e.read() or b"").decode("utf-8", errors="replace")
        elapsed = (time.monotonic() - t0) * 1000
        resp_headers = {k.lower(): v for k, v in e.headers.items()} if e.headers else {}
        return e.code, resp_headers, resp_body, elapsed
    except Exception as e:
        elapsed = (time.monotonic() - t0) * 1000
        return 0, {}, str(e), elapsed


# ── Template execution ───────────────────────────────────────────────────

class TemplateResult:
    """Result of running a single template against a target."""
    __slots__ = ("template_id", "template_name", "severity", "matched",
                 "target", "matched_at", "extracted", "requests",
                 "elapsed_ms", "error")

    def __init__(self, template: Template, target: str):
        self.template_id = template.info.id
        self.template_name = template.info.name
        self.severity = template.info.severity
        self.matched = False
        self.target = target
        self.matched_at = ""
        self.extracted: Dict[str, List[str]] = {}
        self.requests: List[Dict] = []
        self.elapsed_ms = 0.0
        self.error = ""

    def to_dict(self) -> dict:
        d = {
            "template_id": self.template_id,
            "template_name": self.template_name,
            "severity": self.severity,
            "matched": self.matched,
            "target": self.target,
        }
        if self.matched_at:
            d["matched_at"] = self.matched_at
        if self.extracted:
            d["extracted"] = self.extracted
        if self.error:
            d["error"] = self.error
        d["elapsed_ms"] = round(self.elapsed_ms, 1)
        return d


def run_template(template: Template, target: str,
                 verify_ssl: bool = False, timeout: int = 10,
                 extra_vars: Optional[dict] = None,
                 verbose: bool = False) -> TemplateResult:
    """Execute a template against a target URL.

    Returns a TemplateResult indicating whether any matchers matched.
    """
    result = TemplateResult(template, target)
    t0 = time.monotonic()

    # Build base variables
    parsed = urllib.parse.urlparse(target)
    variables = {
        "BaseURL": target.rstrip("/"),
        "RootURL": f"{parsed.scheme}://{parsed.netloc}",
        "Hostname": parsed.hostname or "",
        "Host": parsed.netloc,
        "Port": str(parsed.port or (443 if parsed.scheme == "https" else 80)),
        "Path": parsed.path or "/",
        "Scheme": parsed.scheme,
    }
    if extra_vars:
        variables.update(extra_vars)

    # Execute each request step
    for step_idx, req_step in enumerate(template.requests):
        step_matched = False

        for path_template in req_step.paths:
            url = _interpolate(path_template, variables)
            method = req_step.method
            body = _interpolate(req_step.body, variables) if req_step.body else None
            headers = {k: _interpolate(v, variables) for k, v in req_step.headers.items()}

            if verbose:
                sys.stderr.write(f"  [{template.info.id}] {method} {url}\n")

            status, resp_headers, resp_body, elapsed = _send_request(
                method, url, headers, body, verify=verify_ssl, timeout=timeout
            )

            result.requests.append({
                "method": method, "url": url,
                "status": status, "elapsed_ms": round(elapsed, 1),
                "body_length": len(resp_body),
            })

            # Run extractors — populate variables for next steps
            for extractor in req_step.extractors:
                values = extractor.extract(status, resp_headers, resp_body)
                if values:
                    if extractor.name:
                        variables[extractor.name] = values[0]
                    if not extractor.internal:
                        result.extracted[extractor.name or f"extract_{step_idx}"] = values

            # Run matchers
            if req_step.matchers:
                matcher_results = [
                    m.evaluate(status, resp_headers, resp_body)
                    for m in req_step.matchers
                ]
                if req_step.matchers_condition == "and":
                    step_matched = all(matcher_results)
                else:
                    step_matched = any(matcher_results)

                if step_matched:
                    result.matched = True
                    result.matched_at = url
                    break  # Don't need to try more paths
            elif not req_step.matchers and req_step.extractors:
                # Extraction-only step (e.g., CSRF token grab) — always "passes"
                pass

        if result.matched:
            break  # Stop on first match for multi-path templates

    result.elapsed_ms = (time.monotonic() - t0) * 1000
    return result


def run_templates(templates: List[Template], target: str,
                  verify_ssl: bool = False, timeout: int = 10,
                  tags: Optional[List[str]] = None,
                  severity: Optional[List[str]] = None,
                  extra_vars: Optional[dict] = None,
                  verbose: bool = False) -> List[TemplateResult]:
    """Run multiple templates against a target.

    Args:
        templates: List of loaded templates.
        target: Target URL.
        tags: Only run templates matching these tags.
        severity: Only run templates matching these severity levels.
        verbose: Print progress to stderr.

    Returns:
        List of TemplateResult objects (all results, not just matches).
    """
    results = []
    for tpl in templates:
        # Tag filter
        if tags:
            if not any(t in tpl.info.tags for t in tags):
                continue
        # Severity filter
        if severity:
            if tpl.info.severity not in severity:
                continue

        r = run_template(tpl, target, verify_ssl=verify_ssl,
                         timeout=timeout, extra_vars=extra_vars,
                         verbose=verbose)
        results.append(r)
    return results


# ── Template validation ──────────────────────────────────────────────────

def validate_template(path: str) -> List[str]:
    """Validate a YAML template file. Returns list of error strings (empty = valid)."""
    errors = []
    try:
        text = Path(path).read_text(encoding="utf-8")
    except Exception as e:
        return [f"Cannot read file: {e}"]

    try:
        data = _load_yaml(text)
    except Exception as e:
        return [f"Invalid YAML: {e}"]

    if not isinstance(data, dict):
        return ["Template must be a YAML mapping"]

    if "id" not in data:
        errors.append("Missing required field: id")

    info = data.get("info", {})
    if not isinstance(info, dict):
        errors.append("'info' must be a mapping")
    else:
        if "name" not in info:
            errors.append("Missing info.name")
        if "severity" not in info:
            errors.append("Missing info.severity")
        elif info["severity"] not in ("critical", "high", "medium", "low", "info"):
            errors.append(f"Invalid severity: {info['severity']} (must be critical/high/medium/low/info)")

    http_section = data.get("http", [])
    if not http_section:
        errors.append("Missing 'http' section (no request steps)")
    elif isinstance(http_section, list):
        for i, step in enumerate(http_section):
            if not isinstance(step, dict):
                errors.append(f"http[{i}] must be a mapping")
                continue
            if "path" not in step:
                errors.append(f"http[{i}] missing 'path'")
            paths = step.get("path", [])
            if isinstance(paths, str):
                paths = [paths]
            for p in paths:
                if "{{BaseURL}}" not in p and "{{RootURL}}" not in p and not p.startswith("http"):
                    errors.append(f"http[{i}] path should use {{{{BaseURL}}}} or be absolute: {p}")

    return errors


# ── Scaffold helper ──────────────────────────────────────────────────────

_TEMPLATE_SCAFFOLD = """id: {id}
info:
  name: {name}
  author: {author}
  severity: {severity}
  description: {description}
  tags:
    - custom

http:
  - method: GET
    path:
      - "{{{{BaseURL}}}}/{path}"
    matchers-condition: and
    matchers:
      - type: status
        status:
          - 200
      - type: word
        words:
          - "{match_word}"
        part: body
"""


def scaffold_template(template_id: str = "custom-check",
                      name: str = "Custom Check",
                      author: str = "",
                      severity: str = "info",
                      description: str = "Custom security check",
                      path: str = "vulnerable-endpoint",
                      match_word: str = "sensitive-data") -> str:
    """Generate a scaffold YAML template string."""
    return _TEMPLATE_SCAFFOLD.format(
        id=template_id, name=name, author=author,
        severity=severity, description=description,
        path=path, match_word=match_word,
    )
