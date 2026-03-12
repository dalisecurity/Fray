"""
Fray Template Engine — Nuclei-like YAML DSL with WAF-Aware Bypass Logic

Usage:
    fray template run vuln-check.yaml -t https://example.com
    fray template run templates/ -t https://example.com
    fray template list
    fray template validate vuln-check.yaml

Template format (YAML):
    id: cve-2024-1234
    info:
      name: Example Vulnerability Check
      author: dalisec
      severity: high
      tags: cve,rce,apache
      description: Checks for CVE-2024-1234
      reference:
        - https://nvd.nist.gov/vuln/detail/CVE-2024-1234
    requests:
      - method: GET
        path:
          - "{{BaseURL}}/vulnerable-path"
        headers:
          User-Agent: "Mozilla/5.0"
        matchers-condition: and
        matchers:
          - type: status
            status: [200]
          - type: word
            words: ["vulnerable_string"]
            part: body
          - type: regex
            regex: ["version[\":]\\s*[\"']?(\\d+\\.\\d+)"]
            part: body
        extractors:
          - type: regex
            regex: ["version[\":]\\s*[\"']?(\\d+\\.\\d+)"]
            group: 1
            part: body
        waf-bypass:
          enabled: true
          encode: [url, double-url, unicode]
          case-swap: true

Zero external dependencies — uses stdlib yaml-subset parser.
"""

import json
import os
import re
import ssl
import http.client
import time
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ── Minimal YAML Parser (stdlib, no PyYAML needed) ──────────────────────

def _parse_yaml(text: str) -> Dict[str, Any]:
    """Parse a subset of YAML sufficient for Nuclei-style templates.

    Supports: scalars, lists (- item), nested dicts inside lists,
    flow lists [a, b], references like {{BaseURL}}.
    Does NOT support: anchors, aliases, complex keys, multi-doc.
    """
    lines = [(len(l) - len(l.lstrip()), l.strip()) for l in text.split("\n")]
    # Filter empty/comment lines but keep indices for indent tracking
    filtered = [(indent, stripped, i) for i, (indent, stripped) in enumerate(lines)
                if stripped and not stripped.startswith("#")]

    def _parse_block(start: int, min_indent: int) -> Tuple[Any, int]:
        """Recursively parse a block starting at `start` index.
        Returns (parsed_value, next_index)."""
        if start >= len(filtered):
            return {}, start

        indent, line, _ = filtered[start]

        # Detect if this block is a list or dict
        if line.startswith("- "):
            return _parse_list(start, indent)
        else:
            return _parse_dict(start, indent)

    def _parse_dict(start: int, base_indent: int) -> Tuple[Dict[str, Any], int]:
        result: Dict[str, Any] = {}
        idx = start
        while idx < len(filtered):
            indent, line, _ = filtered[idx]
            if indent < base_indent:
                break
            if indent > base_indent:
                # Skip — already consumed by a sub-block
                idx += 1
                continue

            if line.startswith("- "):
                break  # This is a list, not our dict

            if ":" not in line:
                idx += 1
                continue

            # Find the colon (not inside quotes)
            colon_pos = _find_colon(line)
            if colon_pos < 0:
                idx += 1
                continue

            key = line[:colon_pos].strip().strip('"').strip("'")
            value_str = line[colon_pos + 1:].strip()

            if value_str:
                if value_str.startswith("[") and value_str.endswith("]"):
                    result[key] = [_parse_scalar(x.strip()) for x in _split_flow(value_str[1:-1])]
                else:
                    result[key] = _parse_scalar(value_str)
                idx += 1
            else:
                # Value is a sub-block on next lines
                if idx + 1 < len(filtered):
                    next_indent = filtered[idx + 1][0]
                    if next_indent > indent:
                        sub_val, idx = _parse_block(idx + 1, next_indent)
                        result[key] = sub_val
                    else:
                        result[key] = {}
                        idx += 1
                else:
                    result[key] = {}
                    idx += 1

        return result, idx

    def _parse_list(start: int, base_indent: int) -> Tuple[List[Any], int]:
        result: List[Any] = []
        idx = start
        while idx < len(filtered):
            indent, line, _ = filtered[idx]
            if indent < base_indent:
                break
            if indent > base_indent:
                idx += 1
                continue
            if not line.startswith("- "):
                break

            item_str = line[2:].strip()

            if not item_str:
                # Empty list item — sub-block dict
                if idx + 1 < len(filtered):
                    next_indent = filtered[idx + 1][0]
                    if next_indent > indent:
                        sub_val, idx = _parse_block(idx + 1, next_indent)
                        result.append(sub_val)
                        continue
                result.append("")
                idx += 1
            elif ":" in item_str and not (item_str.startswith('"') or item_str.startswith("'")):
                # Dict item: "- key: value" possibly with more keys below
                colon_pos = _find_colon(item_str)
                if colon_pos >= 0:
                    k = item_str[:colon_pos].strip()
                    v_str = item_str[colon_pos + 1:].strip()
                    item_dict: Dict[str, Any] = {}
                    if v_str:
                        if v_str.startswith("[") and v_str.endswith("]"):
                            item_dict[k] = [_parse_scalar(x.strip()) for x in _split_flow(v_str[1:-1])]
                        else:
                            item_dict[k] = _parse_scalar(v_str)
                    else:
                        # Sub-block value
                        if idx + 1 < len(filtered):
                            ni = filtered[idx + 1][0]
                            # The content indent for "- key:\n  subkey: val" is indent+2
                            list_content_indent = indent + 2
                            if ni >= list_content_indent:
                                sub_val, _ = _parse_block(idx + 1, ni)
                                item_dict[k] = sub_val

                    # Consume continuation keys at same content indent
                    content_indent = indent + 2  # "- " takes 2 chars
                    idx += 1
                    while idx < len(filtered):
                        ci, cl, _ = filtered[idx]
                        if ci < content_indent:
                            break
                        if ci == content_indent and not cl.startswith("- "):
                            cp2 = _find_colon(cl)
                            if cp2 >= 0:
                                ck = cl[:cp2].strip().strip('"').strip("'")
                                cv_str = cl[cp2 + 1:].strip()
                                if cv_str:
                                    if cv_str.startswith("[") and cv_str.endswith("]"):
                                        item_dict[ck] = [_parse_scalar(x.strip()) for x in _split_flow(cv_str[1:-1])]
                                    else:
                                        item_dict[ck] = _parse_scalar(cv_str)
                                    idx += 1
                                else:
                                    if idx + 1 < len(filtered):
                                        ni2 = filtered[idx + 1][0]
                                        if ni2 > ci:
                                            sub2, idx = _parse_block(idx + 1, ni2)
                                            item_dict[ck] = sub2
                                        else:
                                            item_dict[ck] = {}
                                            idx += 1
                                    else:
                                        item_dict[ck] = {}
                                        idx += 1
                            else:
                                idx += 1
                        elif ci > content_indent:
                            idx += 1  # consumed by sub-block
                        else:
                            break

                    result.append(item_dict)
                else:
                    result.append(_parse_scalar(item_str))
                    idx += 1
            elif item_str.startswith("[") and item_str.endswith("]"):
                result.append([_parse_scalar(x.strip()) for x in _split_flow(item_str[1:-1])])
                idx += 1
            else:
                result.append(_parse_scalar(item_str))
                idx += 1

        return result, idx

    def _find_colon(s: str) -> int:
        """Find first colon not inside quotes."""
        in_quote = ""
        for i, c in enumerate(s):
            if c in ('"', "'") and not in_quote:
                in_quote = c
            elif c == in_quote:
                in_quote = ""
            elif c == ":" and not in_quote:
                return i
        return -1

    if not filtered:
        return {}
    val, _ = _parse_block(0, filtered[0][0])
    return val if isinstance(val, dict) else {"data": val}


def _split_flow(s: str) -> List[str]:
    """Split flow sequence respecting quotes."""
    parts = []
    current = ""
    in_quote = ""
    for ch in s:
        if ch in ('"', "'") and not in_quote:
            in_quote = ch
        elif ch == in_quote:
            in_quote = ""
        elif ch == "," and not in_quote:
            parts.append(current)
            current = ""
            continue
        current += ch
    if current.strip():
        parts.append(current)
    return parts


def _parse_scalar(s: str) -> Any:
    """Parse a YAML scalar value."""
    if not s:
        return ""
    # Strip quotes
    if (s.startswith('"') and s.endswith('"')) or \
       (s.startswith("'") and s.endswith("'")):
        return s[1:-1]
    # Booleans
    if s.lower() in ("true", "yes"):
        return True
    if s.lower() in ("false", "no"):
        return False
    # Numbers
    try:
        if "." in s:
            return float(s)
        return int(s)
    except ValueError:
        pass
    return s


# ── Template Model ──────────────────────────────────────────────────────

class Template:
    """Parsed Fray/Nuclei-compatible template."""

    def __init__(self, data: Dict[str, Any], path: str = ""):
        self.raw = data
        self.path = path
        self.id = data.get("id", "unknown")
        info = data.get("info", {})
        self.name = info.get("name", self.id)
        self.author = info.get("author", "")
        self.severity = info.get("severity", "info")
        self.tags = self._parse_tags(info.get("tags", ""))
        self.description = info.get("description", "")
        self.references = info.get("reference", [])
        if isinstance(self.references, str):
            self.references = [self.references]
        self.requests = data.get("requests", [])
        if isinstance(self.requests, dict):
            self.requests = [self.requests]

    @staticmethod
    def _parse_tags(tags) -> List[str]:
        if isinstance(tags, list):
            return tags
        if isinstance(tags, str):
            return [t.strip() for t in tags.split(",") if t.strip()]
        return []

    @classmethod
    def from_file(cls, path: str) -> "Template":
        """Load template from YAML file."""
        text = Path(path).read_text(encoding="utf-8")
        data = _parse_yaml(text)
        return cls(data, path=path)

    @classmethod
    def from_string(cls, text: str) -> "Template":
        """Load template from YAML string."""
        data = _parse_yaml(text)
        return cls(data)

    def validate(self) -> List[str]:
        """Validate template structure. Returns list of errors."""
        errors = []
        if not self.id or self.id == "unknown":
            errors.append("Missing 'id' field")
        if not self.name:
            errors.append("Missing 'info.name' field")
        if self.severity not in ("info", "low", "medium", "high", "critical"):
            errors.append(f"Invalid severity: {self.severity}")
        if not self.requests:
            errors.append("No 'requests' defined")
        for i, req in enumerate(self.requests):
            if not req.get("method"):
                errors.append(f"Request {i}: missing 'method'")
            if not req.get("path"):
                errors.append(f"Request {i}: missing 'path'")
            matchers = req.get("matchers", [])
            for j, m in enumerate(matchers):
                mtype = m.get("type", "")
                if mtype not in ("status", "word", "regex", "size", "binary", "dsl"):
                    errors.append(f"Request {i}, matcher {j}: unknown type '{mtype}'")
        return errors

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "author": self.author,
            "severity": self.severity,
            "tags": self.tags,
            "description": self.description,
        }


# ── Template Runner ─────────────────────────────────────────────────────

class TemplateResult:
    """Result of running a template against a target."""

    def __init__(self, template: Template, target: str):
        self.template = template
        self.target = target
        self.matched = False
        self.extracted: Dict[str, str] = {}
        self.requests_made = 0
        self.duration_ms = 0
        self.match_details: List[Dict[str, Any]] = []
        self.error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d = {
            "template_id": self.template.id,
            "template_name": self.template.name,
            "severity": self.template.severity,
            "target": self.target,
            "matched": self.matched,
            "requests_made": self.requests_made,
            "duration_ms": self.duration_ms,
        }
        if self.extracted:
            d["extracted"] = self.extracted
        if self.match_details:
            d["match_details"] = self.match_details
        if self.error:
            d["error"] = self.error
        return d


class TemplateRunner:
    """Execute templates against targets."""

    def __init__(self, timeout: int = 10, verify_ssl: bool = True,
                 waf_bypass: bool = True, verbose: bool = False):
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.waf_bypass = waf_bypass
        self.verbose = verbose

    def run(self, template: Template, target: str) -> TemplateResult:
        """Run a single template against a target."""
        result = TemplateResult(template, target)
        t0 = time.monotonic()

        parsed = urllib.parse.urlparse(target)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        host = parsed.hostname or ""
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        use_ssl = parsed.scheme == "https"

        try:
            for req_def in template.requests:
                method = req_def.get("method", "GET").upper()
                paths = req_def.get("path", [])
                if isinstance(paths, str):
                    paths = [paths]

                req_headers = dict(req_def.get("headers", {}))
                req_body = req_def.get("body", "")

                matchers = req_def.get("matchers", [])
                matchers_condition = req_def.get("matchers-condition", "or")
                extractors = req_def.get("extractors", [])

                # WAF bypass config
                bypass_cfg = req_def.get("waf-bypass", {})
                do_bypass = self.waf_bypass and bypass_cfg.get("enabled", False)

                for path_template in paths:
                    # Replace variables
                    path = self._interpolate(path_template, base_url, host)
                    body = self._interpolate(req_body, base_url, host) if req_body else None

                    # Make request
                    status, resp_body, resp_headers = self._request(
                        host, port, use_ssl, method, path,
                        headers=req_headers, body=body,
                    )
                    result.requests_made += 1

                    if status == 0:
                        continue

                    # Check matchers
                    matched_list = []
                    for matcher in matchers:
                        m = self._check_matcher(matcher, status, resp_body, resp_headers)
                        matched_list.append(m)

                    if matchers_condition == "and":
                        all_matched = all(matched_list) if matched_list else False
                    else:  # or
                        all_matched = any(matched_list) if matched_list else False

                    if all_matched:
                        result.matched = True
                        result.match_details.append({
                            "path": path,
                            "status": status,
                            "matchers_matched": sum(matched_list),
                        })

                    # Run extractors
                    for extractor in extractors:
                        extracted = self._run_extractor(extractor, resp_body, resp_headers)
                        result.extracted.update(extracted)

                    # WAF bypass: if blocked, try encoded variants
                    if do_bypass and status in (403, 406, 429, 503):
                        encodings = bypass_cfg.get("encode", [])
                        for enc in encodings:
                            encoded_path = self._encode_path(path, enc)
                            if encoded_path == path:
                                continue
                            s2, b2, h2 = self._request(
                                host, port, use_ssl, method, encoded_path,
                                headers=req_headers, body=body,
                            )
                            result.requests_made += 1
                            if s2 not in (403, 406, 429, 503) and s2 > 0:
                                matched2 = []
                                for matcher in matchers:
                                    matched2.append(self._check_matcher(matcher, s2, b2, h2))
                                if (matchers_condition == "and" and all(matched2)) or \
                                   (matchers_condition == "or" and any(matched2)):
                                    result.matched = True
                                    result.match_details.append({
                                        "path": encoded_path,
                                        "status": s2,
                                        "bypass_encoding": enc,
                                    })
                                break

        except Exception as e:
            result.error = str(e)

        result.duration_ms = int((time.monotonic() - t0) * 1000)
        return result

    def run_batch(self, templates: List[Template], targets: List[str],
                  callback=None) -> List[TemplateResult]:
        """Run multiple templates against multiple targets."""
        results = []
        for target in targets:
            for template in templates:
                r = self.run(template, target)
                results.append(r)
                if callback:
                    callback(r)
        return results

    def _interpolate(self, s: str, base_url: str, host: str) -> str:
        """Replace template variables."""
        s = s.replace("{{BaseURL}}", base_url)
        s = s.replace("{{Hostname}}", host)
        s = s.replace("{{Host}}", host)
        return s

    def _request(self, host: str, port: int, use_ssl: bool,
                 method: str, path: str,
                 headers: Optional[Dict[str, str]] = None,
                 body: Optional[str] = None,
                 ) -> Tuple[int, str, Dict[str, str]]:
        """Make an HTTP request. Returns (status, body, headers)."""
        hdrs = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "*/*",
            "Connection": "close",
        }
        if headers:
            hdrs.update(headers)

        try:
            if use_ssl:
                ctx = ssl.create_default_context()
                if not self.verify_ssl:
                    ctx.check_hostname = False
                    ctx.verify_mode = ssl.CERT_NONE
                conn = http.client.HTTPSConnection(host, port, timeout=self.timeout, context=ctx)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=self.timeout)

            body_bytes = body.encode("utf-8") if body else None
            conn.request(method, path, body=body_bytes, headers=hdrs)
            resp = conn.getresponse()
            resp_body = resp.read(1024 * 256).decode("utf-8", errors="replace")
            resp_hdrs = {k.lower(): v for k, v in resp.getheaders()}
            status = resp.status
            conn.close()
            return status, resp_body, resp_hdrs
        except Exception:
            return 0, "", {}

    def _check_matcher(self, matcher: Dict[str, Any],
                       status: int, body: str,
                       headers: Dict[str, str]) -> bool:
        """Check if a matcher matches the response."""
        mtype = matcher.get("type", "")
        part = matcher.get("part", "body")
        negative = matcher.get("negative", False)

        # Select data to match against
        if part == "header":
            data = "\n".join(f"{k}: {v}" for k, v in headers.items())
        elif part == "status":
            data = str(status)
        else:
            data = body

        matched = False

        if mtype == "status":
            status_list = matcher.get("status", [])
            matched = status in status_list

        elif mtype == "word":
            words = matcher.get("words", [])
            condition = matcher.get("condition", "or")
            word_matches = [w.lower() in data.lower() for w in words]
            if condition == "and":
                matched = all(word_matches) if word_matches else False
            else:
                matched = any(word_matches) if word_matches else False

        elif mtype == "regex":
            regexes = matcher.get("regex", [])
            for pattern in regexes:
                try:
                    if re.search(pattern, data, re.IGNORECASE | re.MULTILINE):
                        matched = True
                        break
                except re.error:
                    pass

        elif mtype == "size":
            sizes = matcher.get("size", [])
            matched = len(body) in sizes

        if negative:
            matched = not matched

        return matched

    def _run_extractor(self, extractor: Dict[str, Any],
                       body: str, headers: Dict[str, str]) -> Dict[str, str]:
        """Run an extractor on the response."""
        etype = extractor.get("type", "")
        part = extractor.get("part", "body")
        name = extractor.get("name", etype)
        group = extractor.get("group", 0)

        data = body if part == "body" else "\n".join(f"{k}: {v}" for k, v in headers.items())

        results = {}

        if etype == "regex":
            regexes = extractor.get("regex", [])
            for pattern in regexes:
                try:
                    m = re.search(pattern, data, re.IGNORECASE)
                    if m:
                        results[name] = m.group(group) if group <= len(m.groups()) else m.group(0)
                except re.error:
                    pass

        elif etype == "kv":
            # Key-value extraction from JSON
            try:
                d = json.loads(data)
                keys = extractor.get("keys", [])
                for k in keys:
                    if k in d:
                        results[k] = str(d[k])
            except (json.JSONDecodeError, TypeError):
                pass

        return results

    @staticmethod
    def _encode_path(path: str, encoding: str) -> str:
        """Apply WAF bypass encoding to a path."""
        if encoding == "url":
            # URL-encode special chars
            return urllib.parse.quote(path, safe="/")
        elif encoding == "double-url":
            return urllib.parse.quote(urllib.parse.quote(path, safe="/"), safe="/")
        elif encoding == "unicode":
            # Unicode normalization bypass
            return path.replace("/", "%c0%af")
        elif encoding == "case-swap":
            # Random case swap
            return "".join(
                c.upper() if i % 2 else c.lower()
                for i, c in enumerate(path)
            )
        elif encoding == "path-traversal":
            # Add ../ tricks
            return path.replace("/", "/./")
        return path


# ── Template Discovery ──────────────────────────────────────────────────

def load_templates(path: str, tags: Optional[List[str]] = None,
                   severity: Optional[List[str]] = None,
                   ) -> List[Template]:
    """Load templates from a file or directory.

    Args:
        path: File path or directory to scan for .yaml files
        tags: Filter by tags (any match)
        severity: Filter by severity levels
    """
    templates = []
    p = Path(path)

    if p.is_file():
        try:
            t = Template.from_file(str(p))
            templates.append(t)
        except Exception:
            pass
    elif p.is_dir():
        for yaml_file in sorted(p.rglob("*.yaml")):
            try:
                t = Template.from_file(str(yaml_file))
                templates.append(t)
            except Exception:
                continue

    # Apply filters
    if tags:
        tag_set = set(t.lower() for t in tags)
        templates = [t for t in templates if set(t.tags) & tag_set]

    if severity:
        sev_set = set(s.lower() for s in severity)
        templates = [t for t in templates if t.severity in sev_set]

    return templates


# ── CLI Integration ─────────────────────────────────────────────────────

def run_template(args) -> int:
    """CLI entry point for `fray template run`."""
    try:
        from fray.output import console
    except ImportError:
        console = None

    template_path = args.template_path
    targets = args.targets if hasattr(args, "targets") else [args.target]

    # Load templates
    tags = args.tags.split(",") if hasattr(args, "tags") and args.tags else None
    severity = args.severity.split(",") if hasattr(args, "severity") and args.severity else None
    templates = load_templates(template_path, tags=tags, severity=severity)

    if not templates:
        if console:
            console.print("[red]No templates found[/red]")
        return 1

    if console:
        console.print(f"\n  [bold cyan]Fray Template Engine[/bold cyan]")
        console.print(f"  Templates: [cyan]{len(templates)}[/cyan]")
        console.print(f"  Targets: [green]{len(targets)}[/green]")
        console.print()

    runner = TemplateRunner(
        timeout=getattr(args, "timeout", 10) or 10,
        verify_ssl=not getattr(args, "insecure", False),
        waf_bypass=not getattr(args, "no_waf_bypass", False),
        verbose=getattr(args, "verbose", False),
    )

    findings = []

    def _on_result(r: TemplateResult):
        if r.matched:
            findings.append(r)
            if console:
                sev_colors = {"critical": "red bold", "high": "red",
                              "medium": "yellow", "low": "cyan", "info": "dim"}
                sc = sev_colors.get(r.template.severity, "dim")
                console.print(
                    f"  [{sc}][{r.template.severity.upper()}][/{sc}]"
                    f"  {r.template.name}"
                    f"  [dim]({r.target})[/dim]"
                    f"  [dim]{r.duration_ms}ms[/dim]"
                )
                if r.extracted:
                    for k, v in r.extracted.items():
                        console.print(f"    [dim]{k}: {v}[/dim]")

    runner.run_batch(templates, targets, callback=_on_result)

    if console:
        console.print(f"\n  [bold]Findings:[/bold] {len(findings)} matched")
        console.print()

    return 0 if findings else 1
