"""Fray Template DSL — YAML-based security test templates.

Nuclei-inspired format with WAF-aware bypass logic, mutation support,
and integration with Fray's existing tester/mutator/bypass engine.

Template format:
    id: cve-2024-1234-xss
    info:
      name: CVE-2024-1234 Reflected XSS
      author: dalisecurity
      severity: high
      tags: [xss, cve, reflected]
      description: Reflected XSS via q parameter
      reference: https://nvd.nist.gov/vuln/detail/CVE-2024-1234
    http:
      - method: GET
        path: /search?q={{payload}}
        payloads:
          - '<script>alert(1)</script>'
          - '<img src=x onerror=alert(1)>'
        matchers:
          - type: word
            words: ['<script>alert(1)</script>']
            part: body
          - type: status
            status: [200]
        waf_bypass:
          mutations: true
          max_mutations: 5
          strategies: [unicode_escape, html_entity, double_encode]
"""

import hashlib
import json
import os
import re
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


# ── Minimal YAML parser (no PyYAML dependency) ──────────────────────────────

def _parse_yaml(text: str) -> Dict[str, Any]:
    """Parse a subset of YAML sufficient for Fray templates.

    Supports: scalars, lists (- item), nested dicts (indentation), flow
    sequences [a, b], quoted strings, multi-line strings, comments.
    Falls back to PyYAML if available.
    """
    try:
        import yaml
        return yaml.safe_load(text) or {}
    except ImportError:
        pass
    return _mini_yaml_parse(text)


def _mini_yaml_parse(text: str) -> Dict[str, Any]:
    """Minimal recursive-descent YAML parser for template files."""
    lines = []
    for raw in text.split('\n'):
        # Strip comments (but not inside quotes)
        stripped = raw.rstrip()
        if stripped.lstrip().startswith('#'):
            continue
        # Simple comment strip: only if # is preceded by space and not in quotes
        if ' #' in stripped:
            in_q = False
            q_char = None
            cut = -1
            for i, ch in enumerate(stripped):
                if ch in ('"', "'") and not in_q:
                    in_q = True
                    q_char = ch
                elif ch == q_char and in_q:
                    in_q = False
                elif ch == '#' and not in_q and i > 0 and stripped[i-1] == ' ':
                    cut = i - 1
                    break
            if cut >= 0:
                stripped = stripped[:cut].rstrip()
        lines.append(stripped)

    def _indent(line: str) -> int:
        return len(line) - len(line.lstrip())

    def _parse_value(val: str) -> Any:
        val = val.strip()
        if not val:
            return None
        # Boolean
        if val.lower() in ('true', 'yes', 'on'):
            return True
        if val.lower() in ('false', 'no', 'off'):
            return False
        # None
        if val.lower() in ('null', '~', ''):
            return None
        # Number
        try:
            if '.' in val:
                return float(val)
            return int(val)
        except ValueError:
            pass
        # Flow sequence [a, b, c]
        if val.startswith('[') and val.endswith(']'):
            inner = val[1:-1]
            if not inner.strip():
                return []
            items = []
            for item in _split_flow(inner):
                items.append(_parse_value(item.strip()))
            return items
        # Flow mapping {a: b, c: d}
        if val.startswith('{') and val.endswith('}'):
            inner = val[1:-1]
            if not inner.strip():
                return {}
            result = {}
            for pair in _split_flow(inner):
                if ':' in pair:
                    k, v = pair.split(':', 1)
                    result[k.strip().strip('"').strip("'")] = _parse_value(v)
            return result
        # Quoted string
        if (val.startswith('"') and val.endswith('"')) or \
           (val.startswith("'") and val.endswith("'")):
            return val[1:-1]
        return val

    def _split_flow(s: str) -> List[str]:
        """Split flow sequence/mapping respecting nested brackets and quotes."""
        parts = []
        depth = 0
        current = ''
        in_q = False
        q_char = None
        for ch in s:
            if ch in ('"', "'") and not in_q:
                in_q = True
                q_char = ch
                current += ch
            elif ch == q_char and in_q:
                in_q = False
                current += ch
            elif ch in ('[', '{') and not in_q:
                depth += 1
                current += ch
            elif ch in (']', '}') and not in_q:
                depth -= 1
                current += ch
            elif ch == ',' and depth == 0 and not in_q:
                parts.append(current)
                current = ''
            else:
                current += ch
        if current.strip():
            parts.append(current)
        return parts

    def _parse_block(line_list: List[str], start: int, base_indent: int) -> Tuple[Dict[str, Any], int]:
        result = {}
        i = start
        while i < len(line_list):
            line = line_list[i]
            if not line.strip():
                i += 1
                continue
            ind = _indent(line)
            if ind < base_indent:
                break
            if ind > base_indent:
                i += 1
                continue

            content = line.strip()

            # List item at this level
            if content.startswith('- '):
                # This shouldn't happen at dict level, skip
                i += 1
                continue

            # Key: value
            if ':' in content:
                colon_pos = content.index(':')
                key = content[:colon_pos].strip().strip('"').strip("'")
                val_str = content[colon_pos + 1:].strip()

                if val_str:
                    # Inline value
                    result[key] = _parse_value(val_str)
                    i += 1
                else:
                    # Check next lines for nested content
                    if i + 1 < len(line_list):
                        next_line = line_list[i + 1]
                        if next_line.strip():
                            next_ind = _indent(next_line)
                            if next_ind > ind:
                                if next_line.strip().startswith('- '):
                                    # List
                                    lst, i = _parse_list(line_list, i + 1, next_ind)
                                    result[key] = lst
                                else:
                                    # Nested dict
                                    nested, i = _parse_block(line_list, i + 1, next_ind)
                                    result[key] = nested
                            else:
                                result[key] = None
                                i += 1
                        else:
                            result[key] = None
                            i += 1
                    else:
                        result[key] = None
                        i += 1
            else:
                i += 1

        return result, i

    def _parse_list(line_list: List[str], start: int, base_indent: int) -> Tuple[List[Any], int]:
        result = []
        i = start
        while i < len(line_list):
            line = line_list[i]
            if not line.strip():
                i += 1
                continue
            ind = _indent(line)
            if ind < base_indent:
                break

            content = line.strip()
            if content.startswith('- '):
                item_str = content[2:].strip()
                if ':' in item_str and not item_str.startswith(("'", '"', '[', '{')):
                    # Dict item in list
                    # Re-parse as key: value + following indented lines
                    colon_pos = item_str.index(':')
                    key = item_str[:colon_pos].strip()
                    val_str = item_str[colon_pos + 1:].strip()
                    item_dict = {}
                    if val_str:
                        item_dict[key] = _parse_value(val_str)
                    else:
                        item_dict[key] = None
                    # Check for more keys at deeper indent
                    if i + 1 < len(line_list):
                        nline = line_list[i + 1]
                        nind = _indent(nline)
                        if nind > ind and nline.strip() and not nline.strip().startswith('- '):
                            more, i = _parse_block(line_list, i + 1, nind)
                            item_dict.update(more)
                        else:
                            i += 1
                    else:
                        i += 1
                    result.append(item_dict)
                else:
                    result.append(_parse_value(item_str))
                    i += 1
            else:
                break

        return result, i

    parsed, _ = _parse_block(lines, 0, 0)
    return parsed


def load_yaml_file(path: str) -> Dict[str, Any]:
    """Load and parse a YAML template file."""
    with open(path, 'r', encoding='utf-8') as f:
        return _parse_yaml(f.read())


# ── Template Data Model ─────────────────────────────────────────────────────

@dataclass
class TemplateMatcher:
    """Defines how to match a successful exploit."""
    type: str = "word"           # word, regex, status, size, header, negative
    words: List[str] = field(default_factory=list)
    regex: List[str] = field(default_factory=list)
    status: List[int] = field(default_factory=list)
    size: Optional[int] = None   # body size comparison
    part: str = "body"           # body, header, all, status
    condition: str = "and"       # and, or
    negative: bool = False       # invert match


@dataclass
class TemplateHTTPRequest:
    """A single HTTP request in a template."""
    method: str = "GET"
    path: str = "/"
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    payloads: List[str] = field(default_factory=list)
    matchers: List[TemplateMatcher] = field(default_factory=list)
    follow_redirects: bool = True
    max_redirects: int = 3
    # WAF bypass options
    waf_bypass: bool = False
    mutations: bool = False
    max_mutations: int = 5
    mutation_strategies: List[str] = field(default_factory=list)


@dataclass
class TemplateInfo:
    """Template metadata."""
    name: str = ""
    author: str = ""
    severity: str = "info"       # critical, high, medium, low, info
    tags: List[str] = field(default_factory=list)
    description: str = ""
    reference: List[str] = field(default_factory=list)
    remediation: str = ""
    classification: Dict[str, str] = field(default_factory=dict)  # cve-id, cwe-id, cvss


@dataclass
class Template:
    """A complete Fray security test template."""
    id: str = ""
    info: TemplateInfo = field(default_factory=TemplateInfo)
    http: List[TemplateHTTPRequest] = field(default_factory=list)
    # Template file path (for reference)
    file_path: str = ""

    def validate(self) -> List[str]:
        """Validate template structure. Returns list of error strings."""
        errors = []
        if not self.id:
            errors.append("Missing required field: id")
        if not self.info.name:
            errors.append("Missing required field: info.name")
        if self.info.severity not in ('critical', 'high', 'medium', 'low', 'info'):
            errors.append(f"Invalid severity: {self.info.severity}")
        if not self.http:
            errors.append("No HTTP requests defined")
        for i, req in enumerate(self.http):
            if not req.path:
                errors.append(f"http[{i}]: missing path")
            if not req.payloads and '{{' not in req.path and '{{' not in req.body:
                errors.append(f"http[{i}]: no payloads and no injection markers ({{{{...}}}}) in path/body")
        return errors


# ── Template Parser ──────────────────────────────────────────────────────────

def parse_template(data: Dict[str, Any], file_path: str = "") -> Template:
    """Parse a YAML dict into a Template object."""
    info_data = data.get('info', {})
    refs = info_data.get('reference', [])
    if isinstance(refs, str):
        refs = [refs]

    info = TemplateInfo(
        name=str(info_data.get('name', '')),
        author=str(info_data.get('author', '')),
        severity=str(info_data.get('severity', 'info')).lower(),
        tags=info_data.get('tags', []) or [],
        description=str(info_data.get('description', '')),
        reference=refs,
        remediation=str(info_data.get('remediation', '')),
        classification=info_data.get('classification', {}) or {},
    )

    http_list = []
    for req_data in (data.get('http', []) or []):
        matchers = []
        for m in (req_data.get('matchers', []) or []):
            matchers.append(TemplateMatcher(
                type=str(m.get('type', 'word')),
                words=m.get('words', []) or [],
                regex=m.get('regex', []) or [],
                status=m.get('status', []) or [],
                size=m.get('size'),
                part=str(m.get('part', 'body')),
                condition=str(m.get('condition', 'and')),
                negative=bool(m.get('negative', False)),
            ))

        bypass_data = req_data.get('waf_bypass', {})
        if isinstance(bypass_data, bool):
            bypass_data = {'mutations': bypass_data}
        elif bypass_data is None:
            bypass_data = {}

        payloads = req_data.get('payloads', []) or []
        if isinstance(payloads, str):
            payloads = [payloads]

        http_list.append(TemplateHTTPRequest(
            method=str(req_data.get('method', 'GET')).upper(),
            path=str(req_data.get('path', '/')),
            headers=req_data.get('headers', {}) or {},
            body=str(req_data.get('body', '')),
            payloads=payloads,
            matchers=matchers,
            follow_redirects=bool(req_data.get('follow_redirects', True)),
            max_redirects=int(req_data.get('max_redirects', 3)),
            waf_bypass=bool(bypass_data.get('enabled', bypass_data.get('mutations', False))),
            mutations=bool(bypass_data.get('mutations', False)),
            max_mutations=int(bypass_data.get('max_mutations', 5)),
            mutation_strategies=bypass_data.get('strategies', []) or [],
        ))

    return Template(
        id=str(data.get('id', '')),
        info=info,
        http=http_list,
        file_path=file_path,
    )


def load_template(path: str) -> Template:
    """Load a template from a YAML file."""
    data = load_yaml_file(path)
    return parse_template(data, file_path=path)


def load_template_from_string(text: str) -> Template:
    """Load a template from a YAML string."""
    data = _parse_yaml(text)
    return parse_template(data)


# ── Template Discovery ───────────────────────────────────────────────────────

_TEMPLATE_DIRS = [
    Path.home() / '.fray' / 'templates',
    Path.home() / '.fray' / 'custom-templates',
]


def discover_templates(
    paths: Optional[List[str]] = None,
    tags: Optional[List[str]] = None,
    severity: Optional[List[str]] = None,
    ids: Optional[List[str]] = None,
    authors: Optional[List[str]] = None,
) -> List[Template]:
    """Discover and filter templates from disk.

    Args:
        paths: Explicit file/directory paths. If None, uses default dirs.
        tags: Filter by tags (OR logic).
        severity: Filter by severity levels.
        ids: Filter by template ID patterns (glob-like).
        authors: Filter by author names.
    """
    search_paths = []
    if paths:
        for p in paths:
            search_paths.append(Path(p))
    else:
        search_paths = [d for d in _TEMPLATE_DIRS if d.exists()]

    templates = []
    for sp in search_paths:
        if sp.is_file() and sp.suffix in ('.yaml', '.yml'):
            try:
                templates.append(load_template(str(sp)))
            except Exception:
                pass
        elif sp.is_dir():
            for fp in sorted(sp.rglob('*.yaml')) + sorted(sp.rglob('*.yml')):
                try:
                    templates.append(load_template(str(fp)))
                except Exception:
                    pass

    # Apply filters
    if tags:
        tag_set = set(t.lower() for t in tags)
        templates = [t for t in templates
                     if tag_set & set(tg.lower() for tg in t.info.tags)]
    if severity:
        sev_set = set(s.lower() for s in severity)
        templates = [t for t in templates if t.info.severity in sev_set]
    if ids:
        templates = [t for t in templates
                     if any(_glob_match(pat, t.id) for pat in ids)]
    if authors:
        author_set = set(a.lower() for a in authors)
        templates = [t for t in templates
                     if t.info.author.lower() in author_set]

    return templates


def _glob_match(pattern: str, text: str) -> bool:
    """Simple glob matching: * matches anything."""
    regex = re.escape(pattern).replace(r'\*', '.*')
    return bool(re.fullmatch(regex, text, re.IGNORECASE))


# ── Template Runner ──────────────────────────────────────────────────────────

@dataclass
class TemplateResult:
    """Result of running a single template."""
    template_id: str = ""
    template_name: str = ""
    severity: str = "info"
    matched: bool = False
    target: str = ""
    payloads_tested: int = 0
    payloads_matched: int = 0
    payloads_blocked: int = 0
    matches: List[Dict[str, Any]] = field(default_factory=list)
    duration: float = 0.0
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'template_id': self.template_id,
            'template_name': self.template_name,
            'severity': self.severity,
            'matched': self.matched,
            'target': self.target,
            'payloads_tested': self.payloads_tested,
            'payloads_matched': self.payloads_matched,
            'payloads_blocked': self.payloads_blocked,
            'matches': self.matches,
            'duration': round(self.duration, 3),
            'error': self.error,
        }


def run_template(
    template: Template,
    target: str,
    timeout: int = 8,
    delay: float = 0.3,
    verify_ssl: bool = True,
    custom_headers: Optional[Dict[str, str]] = None,
    verbose: bool = False,
    impersonate: Optional[str] = None,
) -> TemplateResult:
    """Execute a template against a target URL.

    Uses Fray's WAFTester for HTTP requests, with optional mutation support.
    """
    from fray.tester import WAFTester

    result = TemplateResult(
        template_id=template.id,
        template_name=template.info.name,
        severity=template.info.severity,
        target=target,
    )

    t0 = time.time()
    try:
        tester = WAFTester(
            target=target,
            timeout=timeout,
            delay=delay,
            verify_ssl=verify_ssl,
            custom_headers=custom_headers,
            verbose=verbose,
            impersonate=impersonate,
        )

        for req in template.http:
            payloads = req.payloads or ['']
            for payload in payloads:
                # Substitute {{payload}} markers
                path = req.path.replace('{{payload}}', payload)
                body = req.body.replace('{{payload}}', payload) if req.body else ''
                headers = dict(req.headers)
                for k, v in headers.items():
                    headers[k] = v.replace('{{payload}}', payload)

                test_result = tester.test_payload(
                    payload=payload or path,
                    category='custom',
                )
                result.payloads_tested += 1

                if test_result.get('blocked'):
                    result.payloads_blocked += 1

                    # Try mutations if WAF bypass is enabled
                    if req.waf_bypass and req.mutations:
                        mutation_matches = _try_mutations(
                            tester, payload, req, target,
                            max_mutations=req.max_mutations,
                            strategies=req.mutation_strategies,
                        )
                        for mm in mutation_matches:
                            result.payloads_matched += 1
                            result.matches.append(mm)
                    continue

                # Check matchers
                matched = _check_matchers(req.matchers, test_result, payload)
                if matched:
                    result.payloads_matched += 1
                    result.matches.append({
                        'payload': payload,
                        'path': path,
                        'status': test_result.get('status_code', 0),
                        'matched_by': 'direct',
                    })

    except Exception as e:
        result.error = str(e)

    result.duration = time.time() - t0
    result.matched = result.payloads_matched > 0
    return result


def _check_matchers(
    matchers: List[TemplateMatcher],
    test_result: Dict[str, Any],
    payload: str,
) -> bool:
    """Check if test result matches template matchers."""
    if not matchers:
        # No matchers = match on not-blocked
        return not test_result.get('blocked', False)

    results = []
    for m in matchers:
        matched = False

        if m.type == 'word':
            body = test_result.get('body', test_result.get('response_body', ''))
            if m.part == 'header':
                body = str(test_result.get('response_headers', ''))
            elif m.part == 'all':
                body = str(test_result.get('response_headers', '')) + str(body)
            matched = all(w in body for w in m.words) if m.words else False

        elif m.type == 'regex':
            body = test_result.get('body', test_result.get('response_body', ''))
            if m.part == 'header':
                body = str(test_result.get('response_headers', ''))
            matched = any(re.search(r, body) for r in m.regex) if m.regex else False

        elif m.type == 'status':
            status = test_result.get('status_code', 0)
            matched = status in m.status

        elif m.type == 'size':
            body_size = len(test_result.get('body', test_result.get('response_body', '')))
            if m.size is not None:
                matched = body_size == m.size

        elif m.type == 'negative':
            body = test_result.get('body', test_result.get('response_body', ''))
            matched = not any(w in body for w in m.words) if m.words else True

        if m.negative:
            matched = not matched
        results.append(matched)

    if not results:
        return False
    condition = matchers[0].condition if matchers else 'and'
    if condition == 'or':
        return any(results)
    return all(results)


def _try_mutations(
    tester,
    payload: str,
    req: TemplateHTTPRequest,
    target: str,
    max_mutations: int = 5,
    strategies: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Try mutation strategies on a blocked payload."""
    matches = []
    try:
        from fray.mutator import mutate_payload, STRATEGIES

        strats = strategies or list(STRATEGIES.keys())[:max_mutations]
        for strat_name in strats[:max_mutations]:
            try:
                mutated = mutate_payload(payload, strategy=strat_name)
            except Exception:
                continue
            if mutated == payload:
                continue

            result = tester.test_payload(
                payload=mutated,
                category='custom',
            )
            if not result.get('blocked'):
                matched = _check_matchers(req.matchers, result, mutated)
                if matched or not req.matchers:
                    matches.append({
                        'payload': mutated,
                        'original_payload': payload,
                        'mutation_strategy': strat_name,
                        'status': result.get('status_code', 0),
                        'matched_by': 'mutation',
                    })
    except ImportError:
        pass
    return matches


# ── Batch Runner ─────────────────────────────────────────────────────────────

@dataclass
class BatchResult:
    """Result of running multiple templates."""
    target: str = ""
    templates_run: int = 0
    templates_matched: int = 0
    total_payloads: int = 0
    total_matches: int = 0
    total_blocked: int = 0
    results: List[TemplateResult] = field(default_factory=list)
    duration: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'target': self.target,
            'templates_run': self.templates_run,
            'templates_matched': self.templates_matched,
            'total_payloads': self.total_payloads,
            'total_matches': self.total_matches,
            'total_blocked': self.total_blocked,
            'results': [r.to_dict() for r in self.results if r.matched],
            'all_results': [r.to_dict() for r in self.results],
            'duration': round(self.duration, 3),
        }

    def summary_by_severity(self) -> Dict[str, int]:
        counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for r in self.results:
            if r.matched:
                counts[r.severity] = counts.get(r.severity, 0) + 1
        return counts


def run_templates(
    templates: List[Template],
    target: str,
    timeout: int = 8,
    delay: float = 0.3,
    verify_ssl: bool = True,
    custom_headers: Optional[Dict[str, str]] = None,
    verbose: bool = False,
    impersonate: Optional[str] = None,
    callback=None,
) -> BatchResult:
    """Run multiple templates against a target.

    Args:
        callback: Optional function(TemplateResult) called after each template.
    """
    batch = BatchResult(target=target)
    t0 = time.time()

    for tmpl in templates:
        errors = tmpl.validate()
        if errors:
            r = TemplateResult(
                template_id=tmpl.id,
                template_name=tmpl.info.name,
                severity=tmpl.info.severity,
                target=target,
                error='; '.join(errors),
            )
            batch.results.append(r)
            if callback:
                callback(r)
            continue

        r = run_template(
            template=tmpl,
            target=target,
            timeout=timeout,
            delay=delay,
            verify_ssl=verify_ssl,
            custom_headers=custom_headers,
            verbose=verbose,
            impersonate=impersonate,
        )
        batch.results.append(r)
        batch.templates_run += 1
        batch.total_payloads += r.payloads_tested
        batch.total_matches += r.payloads_matched
        batch.total_blocked += r.payloads_blocked
        if r.matched:
            batch.templates_matched += 1
        if callback:
            callback(r)

    batch.duration = time.time() - t0
    return batch


# ── Template Scaffolding ─────────────────────────────────────────────────────

def scaffold_template(
    template_id: str = "my-template",
    name: str = "My Security Test",
    category: str = "xss",
    severity: str = "medium",
    path: str = "/search?q={{payload}}",
) -> str:
    """Generate a template YAML scaffold."""
    payloads = {
        'xss': ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
                 "'\"><svg/onload=alert(1)>"],
        'sqli': ["' OR 1=1--", "1 UNION SELECT NULL--", "' AND '1'='1"],
        'ssrf': ["http://169.254.169.254/latest/meta-data/",
                 "http://127.0.0.1:80/", "http://[::]:80/"],
        'ssti': ["{{7*7}}", "${7*7}", "<%= 7*7 %>"],
        'lfi': ["../../../etc/passwd", "....//....//etc/passwd",
                "..%252f..%252f..%252fetc/passwd"],
        'cmdi': ["; id", "| id", "`id`"],
    }
    p = payloads.get(category, payloads['xss'])
    payload_lines = '\n'.join(f"          - '{pl}'" for pl in p)

    return f"""id: {template_id}

info:
  name: {name}
  author: you
  severity: {severity}
  tags: [{category}, custom]
  description: Custom {category.upper()} test template
  reference:
    - https://owasp.org/

http:
  - method: GET
    path: {path}
    payloads:
{payload_lines}
    matchers:
      - type: word
        words: ['{p[0]}']
        part: body
      - type: status
        status: [200]
    waf_bypass:
      mutations: true
      max_mutations: 5
"""
