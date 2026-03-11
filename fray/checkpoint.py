#!/usr/bin/env python3
"""
Fray Checkpoint — Resume interrupted payload scans.

Saves scan progress to ~/.fray/checkpoints/<domain_hash>.json after each
payload so interrupted scans can be resumed with --resume.

Checkpoint schema:
{
  "target": "https://example.com/path",
  "method": "GET",
  "param": "input",
  "waf_vendor": "cloudflare",
  "total_payloads": 500,
  "tested_hashes": ["<sha256[:16]>", ...],
  "results": [...],
  "started_at": "ISO8601",
  "updated_at": "ISO8601"
}
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

_CHECKPOINT_DIR = Path.home() / ".fray" / "checkpoints"


def _target_hash(target: str) -> str:
    """Deterministic short hash for a target URL."""
    return hashlib.sha256(target.encode()).hexdigest()[:16]


def _payload_hash(payload: str) -> str:
    """Short hash of a payload string."""
    return hashlib.sha256(payload.encode()).hexdigest()[:16]


def _checkpoint_path(target: str) -> Path:
    return _CHECKPOINT_DIR / f"{_target_hash(target)}.json"


def load_checkpoint(target: str) -> Optional[Dict[str, Any]]:
    """Load an existing checkpoint for a target. Returns None if not found."""
    path = _checkpoint_path(target)
    if not path.is_file():
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return None


def save_checkpoint(target: str, method: str, param: str,
                    waf_vendor: str, total_payloads: int,
                    tested_hashes: List[str], results: List[Dict],
                    started_at: str) -> None:
    """Save current scan progress to checkpoint file."""
    _CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
    data = {
        "target": target,
        "method": method,
        "param": param,
        "waf_vendor": waf_vendor,
        "total_payloads": total_payloads,
        "tested_hashes": tested_hashes,
        "results": results,
        "started_at": started_at,
        "updated_at": datetime.now().isoformat(),
    }
    path = _checkpoint_path(target)
    tmp = path.with_suffix(".tmp")
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False)
        tmp.replace(path)
    except OSError:
        pass


def clear_checkpoint(target: str) -> bool:
    """Remove checkpoint file after successful scan completion."""
    path = _checkpoint_path(target)
    try:
        path.unlink(missing_ok=True)
        return True
    except OSError:
        return False


def get_tested_set(checkpoint: Dict[str, Any]) -> Set[str]:
    """Extract set of already-tested payload hashes from checkpoint."""
    return set(checkpoint.get("tested_hashes", []))
