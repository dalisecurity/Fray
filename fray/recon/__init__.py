"""
Fray Recon — Target Reconnaissance & Fingerprinting

Package structure (incrementally refactored from _monolith.py):
  http.py        — URL parsing, SSL context, HTTP GET, TLS audit
  _monolith.py   — remaining implementation (being extracted)

All public symbols are re-exported here so existing imports
like `from fray.recon import run_recon` continue to work.
"""

# ── Extracted submodules ──
from fray.recon.http import (  # noqa: F401
    _parse_url,
    _make_ssl_context,
    _http_get,
    _follow_redirect,
    _post_json,
    _fetch_url,
    check_http,
    check_tls,
    check_tls_grade,
)
from fray.recon.fingerprint import (  # noqa: F401
    check_security_headers,
    check_clickjacking,
    check_captcha,
    check_favicon,
    check_cookies,
    fingerprint_app,
    recommend_categories,
)
from fray.recon.supply_chain import (  # noqa: F401
    _parse_version,
    check_frontend_libs,
    fetch_retirejs_db,
)
from fray.recon.history import (  # noqa: F401
    _load_previous_recon,
    diff_recon,
    print_recon_diff,
)
from fray.recon.dns import (  # noqa: F401
    check_dns,
    check_subdomains_crt,
    check_subdomains_bruteforce,
    discover_origin_ip,
)
from fray.recon.checks import (  # noqa: F401
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
    check_rate_limits_critical,
    check_differential_responses,
    waf_gap_analysis,
)
from fray.recon.discovery import (  # noqa: F401
    discover_historical_urls,
    print_historical_urls,
    mine_params,
    print_mined_params,
    discover_js_endpoints,
    print_js_endpoints,
    discover_params,
)
from fray.recon.pipeline import (  # noqa: F401
    run_recon,
    print_recon,
)

# ── Remaining (from monolith — Colors only) ──
from fray.recon._monolith import Colors  # noqa: F401
