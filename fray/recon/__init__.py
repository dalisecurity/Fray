"""
Fray Recon — Target Reconnaissance & Fingerprinting

Package structure (refactored from monolithic recon.py):
  _monolith.py  — full implementation (being incrementally extracted)

All public symbols are re-exported here so existing imports
like `from fray.recon import run_recon` continue to work.
"""

from fray.recon._monolith import (  # noqa: F401
    # Core utilities
    Colors,
    _parse_url,
    _make_ssl_context,
    _http_get,
    _follow_redirect,
    _post_json,
    _fetch_url,
    # Core checks
    check_http,
    check_tls,
    check_security_headers,
    check_cookies,
    # Fingerprinting
    fingerprint_app,
    recommend_categories,
    # Supply chain
    _parse_version,
    check_frontend_libs,
    # DNS
    check_dns,
    check_subdomains_crt,
    check_subdomains_bruteforce,
    discover_origin_ip,
    # Extended checks
    check_robots_sitemap,
    check_cors,
    check_exposed_files,
    check_http_methods,
    check_error_page,
    check_graphql_introspection,
    check_api_discovery,
    check_host_header_injection,
    check_admin_panels,
    check_rate_limits,
    # WAF analysis
    check_differential_responses,
    waf_gap_analysis,
    # Historical URLs
    discover_historical_urls,
    print_historical_urls,
    # Parameter mining
    discover_params,
    mine_params,
    print_mined_params,
    # JS endpoint extraction
    discover_js_endpoints,
    print_js_endpoints,
    # Pipeline
    run_recon,
    print_recon,
)
