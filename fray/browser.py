#!/usr/bin/env python3
"""
Fray Browser Mode — Playwright-powered crawling for JS-heavy SPAs.

Renders pages in a real browser, waits for JS execution, then extracts:
  - Dynamically generated forms and inputs
  - AJAX/fetch endpoints from network traffic
  - Client-side routing paths
  - JS-injected query parameters

Usage:
    fray scan https://example.com --browser
    fray scan https://example.com --browser --depth 2

Requires: pip install playwright && playwright install chromium
"""

import json
import re
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from urllib.parse import urljoin, urlparse, parse_qs


def check_playwright() -> bool:
    """Check if playwright is installed and browsers are available."""
    try:
        from playwright.sync_api import sync_playwright
        return True
    except ImportError:
        return False


@dataclass
class BrowserEndpoint:
    """An endpoint discovered via browser rendering."""
    url: str
    method: str = "GET"
    source: str = "browser"
    params: List[str] = field(default_factory=list)
    is_ajax: bool = False


def browser_crawl(target: str, max_pages: int = 20, max_depth: int = 2,
                  timeout: int = 15, headless: bool = True,
                  quiet: bool = False) -> Dict:
    """Crawl a target using a real browser (Playwright).

    Args:
        target: Target URL to crawl.
        max_pages: Maximum pages to visit.
        max_depth: Maximum navigation depth.
        timeout: Page load timeout in seconds.
        headless: Run browser in headless mode.
        quiet: Suppress progress output.

    Returns:
        Dict with endpoints, injection_points, ajax_calls, forms, js_routes.
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return {
            "error": "Playwright not installed. Run: pip install playwright && playwright install chromium",
            "endpoints": [],
            "injection_points": [],
            "ajax_calls": [],
            "forms": [],
        }

    result = {
        "target": target,
        "pages_rendered": 0,
        "endpoints": [],
        "injection_points": [],
        "ajax_calls": [],
        "forms": [],
        "js_routes": [],
        "errors": [],
    }

    parsed_target = urlparse(target)
    base_domain = parsed_target.hostname or ""

    visited: Set[str] = set()
    queue: List[Tuple[str, int]] = [(target, 0)]
    ajax_urls: Set[str] = set()
    all_forms: List[Dict] = []
    all_injection_points: List[Dict] = []

    if not quiet:
        try:
            from fray.output import console
            console.print(f"\n  [bold]Browser Mode[/bold]: launching Chromium...")
        except ImportError:
            print("  Browser Mode: launching Chromium...")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=headless)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                       "AppleWebKit/537.36 (KHTML, like Gecko) "
                       "Chrome/122.0.0.0 Safari/537.36",
            viewport={"width": 1280, "height": 720},
        )

        # Intercept network requests to capture AJAX calls
        def _on_request(request):
            url = request.url
            if request.resource_type in ("xhr", "fetch"):
                parsed = urlparse(url)
                if parsed.hostname and (
                    parsed.hostname == base_domain or
                    parsed.hostname.endswith(f".{base_domain}")
                ):
                    ajax_urls.add(url)

        page = context.new_page()
        page.on("request", _on_request)

        while queue and len(visited) < max_pages:
            url, depth = queue.pop(0)

            # Normalize and dedup
            canonical = urlparse(url)._replace(fragment="").geturl()
            if canonical in visited:
                continue

            # Same-origin check
            parsed = urlparse(url)
            if parsed.hostname != base_domain:
                continue

            visited.add(canonical)

            if not quiet:
                try:
                    from fray.output import console
                    console.print(f"  [dim][{len(visited):>3}][/dim] {canonical[:80]}")
                except ImportError:
                    print(f"  [{len(visited):>3}] {canonical[:80]}")

            try:
                page.goto(url, wait_until="networkidle", timeout=timeout * 1000)
                # Wait for any late JS rendering
                page.wait_for_timeout(1000)
            except Exception as e:
                result["errors"].append(f"Failed to load {url}: {str(e)[:100]}")
                continue

            result["pages_rendered"] += 1

            # Extract forms from rendered DOM
            try:
                forms = page.evaluate("""() => {
                    const forms = [];
                    document.querySelectorAll('form').forEach(form => {
                        const inputs = [];
                        form.querySelectorAll('input, textarea, select').forEach(el => {
                            if (el.name) {
                                inputs.push({
                                    name: el.name,
                                    type: el.type || 'text',
                                    id: el.id || '',
                                });
                            }
                        });
                        forms.push({
                            action: form.action || '',
                            method: (form.method || 'GET').toUpperCase(),
                            inputs: inputs,
                        });
                    });
                    return forms;
                }""")
                for form in forms:
                    form["page_url"] = url
                    all_forms.append(form)
                    for inp in form.get("inputs", []):
                        all_injection_points.append({
                            "url": form.get("action") or url,
                            "method": form.get("method", "GET"),
                            "param": inp["name"],
                            "type": inp.get("type", "text"),
                            "source": "browser_form",
                        })
            except Exception:
                pass

            # Extract all links from rendered DOM
            if depth < max_depth:
                try:
                    links = page.evaluate("""() => {
                        const links = [];
                        document.querySelectorAll('a[href]').forEach(a => {
                            links.push(a.href);
                        });
                        return links;
                    }""")
                    for link in links:
                        link_parsed = urlparse(link)
                        if link_parsed.hostname == base_domain:
                            queue.append((link, depth + 1))
                except Exception:
                    pass

            # Extract query params from current URL
            if parsed.query:
                for param_name in parse_qs(parsed.query).keys():
                    all_injection_points.append({
                        "url": url,
                        "method": "GET",
                        "param": param_name,
                        "source": "browser_url",
                    })

            # Extract JS-discovered routes (SPA router paths)
            try:
                js_routes = page.evaluate("""() => {
                    const routes = [];
                    // Check for common SPA router patterns
                    if (window.__NEXT_DATA__) routes.push('nextjs');
                    if (window.__NUXT__) routes.push('nuxt');
                    if (window.React) routes.push('react');
                    if (window.Vue) routes.push('vue');
                    if (window.angular) routes.push('angular');
                    return routes;
                }""")
                for framework in js_routes:
                    if framework not in result["js_routes"]:
                        result["js_routes"].append(framework)
            except Exception:
                pass

        browser.close()

    # Collect AJAX endpoints as injection points
    for ajax_url in ajax_urls:
        parsed = urlparse(ajax_url)
        result["ajax_calls"].append(ajax_url)
        if parsed.query:
            for param_name in parse_qs(parsed.query).keys():
                all_injection_points.append({
                    "url": ajax_url,
                    "method": "GET",
                    "param": param_name,
                    "source": "browser_ajax",
                })

    # Deduplicate injection points
    seen = set()
    for ip in all_injection_points:
        key = f"{ip['method']}:{ip['url']}:{ip['param']}"
        if key not in seen:
            seen.add(key)
            result["injection_points"].append(ip)

    result["endpoints"] = list(visited)
    result["forms"] = all_forms

    if not quiet:
        try:
            from fray.output import console
            console.print(
                f"\n  [bold green]✓[/bold green] Browser crawl: {result['pages_rendered']} pages, "
                f"{len(result['injection_points'])} injection points, "
                f"{len(result['ajax_calls'])} AJAX calls, "
                f"{len(result['forms'])} forms"
            )
            if result["js_routes"]:
                console.print(f"  [dim]SPA frameworks: {', '.join(result['js_routes'])}[/dim]")
        except ImportError:
            pass

    return result
