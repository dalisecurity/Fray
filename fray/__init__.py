"""
Fray — AI-Powered WAF Security Testing Platform

Open-source offensive security toolkit with 5,500+ attack payloads,
25 WAF vendor fingerprints, and AI-native workflows.

Usage:
    pip install fray
    fray detect https://example.com
    fray test https://example.com --category xss
"""

try:
    from importlib.metadata import version as _get_version
    __version__ = _get_version("fray")
except Exception:
    __version__ = "0.0.0-dev"
__author__ = "DALI Security"
__license__ = "MIT"

from pathlib import Path

PACKAGE_DIR = Path(__file__).parent
PAYLOADS_DIR = PACKAGE_DIR / "payloads"
DATA_DIR = PACKAGE_DIR / "data"


def load_waf_intel() -> dict:
    """Load WAF vendor intelligence knowledge base."""
    import json
    intel_path = DATA_DIR / "waf_intel.json"
    if intel_path.exists():
        return json.loads(intel_path.read_text(encoding="utf-8"))
    return {"vendors": {}, "technique_matrix": {}}
