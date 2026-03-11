"""Response diffing utilities for false positive reduction (#219).

Provides structural comparison between baseline and payload responses,
used by the tester and recon modules to classify findings as confirmed,
likely, possible, or noise.
"""

import hashlib
import re
from difflib import SequenceMatcher
from typing import Any, Dict, List, Optional, Tuple


class ResponseDiffer:
    """Compare HTTP responses to a baseline to detect false positives.

    Usage:
        differ = ResponseDiffer()
        differ.add_baseline(status=200, body="<html>...", headers={...}, elapsed_ms=150.0)
        differ.add_baseline(status=200, body="<html>...", headers={...}, elapsed_ms=160.0)
        differ.finalize_baseline()

        verdict = differ.classify(status=200, body="<html>...", elapsed_ms=155.0)
        # verdict = {"similar": True, "similarity": 0.97, "verdict": "identical", ...}
    """

    def __init__(self):
        self._samples: List[Dict[str, Any]] = []
        self._baseline: Optional[Dict[str, Any]] = None

    # ── Baseline collection ───────────────────────────────────────────

    def add_baseline(self, status: int, body: str, headers: Optional[Dict] = None,
                     elapsed_ms: float = 0.0) -> None:
        """Add a baseline response sample."""
        body_hash = hashlib.md5(body.encode("utf-8", errors="replace")).hexdigest()
        tokens = _tokenize_html(body)
        self._samples.append({
            "status": status,
            "body": body,
            "body_len": len(body),
            "body_hash": body_hash,
            "headers": headers or {},
            "elapsed_ms": elapsed_ms,
            "tokens": tokens,
            "tag_count": body.count("<"),
        })

    def finalize_baseline(self) -> Dict[str, Any]:
        """Compute aggregate baseline from collected samples.

        Returns the baseline dict (also stored internally).
        """
        if not self._samples:
            self._baseline = {
                "status": 0, "body_len_avg": 0, "body_len_min": 0,
                "body_len_max": 0, "body_hashes": set(), "elapsed_avg": 0,
                "stable_body": False, "tag_count_avg": 0, "token_set": set(),
            }
            return self._baseline

        statuses = [s["status"] for s in self._samples]
        lengths = [s["body_len"] for s in self._samples]
        timings = [s["elapsed_ms"] for s in self._samples]
        hashes = {s["body_hash"] for s in self._samples}
        tag_counts = [s["tag_count"] for s in self._samples]

        # Union of all tokens across baseline samples
        all_tokens: set = set()
        for s in self._samples:
            all_tokens.update(s["tokens"])

        self._baseline = {
            "status": max(set(statuses), key=statuses.count),
            "body_len_avg": int(sum(lengths) / len(lengths)),
            "body_len_min": min(lengths),
            "body_len_max": max(lengths),
            "body_hashes": hashes,
            "elapsed_avg": sum(timings) / len(timings) if timings else 0,
            "stable_body": len(hashes) == 1,
            "tag_count_avg": int(sum(tag_counts) / len(tag_counts)),
            "token_set": all_tokens,
            "sample_count": len(self._samples),
        }
        return self._baseline

    @property
    def baseline(self) -> Optional[Dict[str, Any]]:
        return self._baseline

    # ── Classification ────────────────────────────────────────────────

    def classify(self, status: int, body: str,
                 elapsed_ms: float = 0.0) -> Dict[str, Any]:
        """Compare a response against the baseline and classify it.

        Returns:
            Dict with:
              - similar (bool): True if response is structurally similar to baseline
              - similarity (float): 0.0-1.0 overall similarity ratio
              - verdict: "identical" | "similar" | "different" | "block_page"
              - body_similarity (float): SequenceMatcher ratio on body
              - token_similarity (float): Jaccard similarity on HTML tokens
              - length_ratio (float): min(a,b)/max(a,b) on body lengths
              - status_match (bool)
              - timing_delta_ms (float)
              - fp_indicators (list): reasons this might be a false positive
        """
        if not self._baseline:
            raise ValueError("Call finalize_baseline() before classify()")

        bl = self._baseline
        result: Dict[str, Any] = {
            "similar": False,
            "similarity": 0.0,
            "verdict": "different",
            "body_similarity": 0.0,
            "token_similarity": 0.0,
            "length_ratio": 0.0,
            "status_match": status == bl["status"],
            "timing_delta_ms": round(elapsed_ms - bl["elapsed_avg"], 1),
            "fp_indicators": [],
        }

        # Body hash check (fastest path)
        body_hash = hashlib.md5(body.encode("utf-8", errors="replace")).hexdigest()
        if body_hash in bl["body_hashes"]:
            result.update(similar=True, similarity=1.0, verdict="identical",
                          body_similarity=1.0, token_similarity=1.0, length_ratio=1.0)
            if bl["stable_body"]:
                result["fp_indicators"].append("body_identical_to_stable_baseline")
            return result

        # Length ratio
        bl_len = bl["body_len_avg"]
        if bl_len > 0 and len(body) > 0:
            result["length_ratio"] = round(min(len(body), bl_len) / max(len(body), bl_len), 3)
        elif bl_len == 0 and len(body) == 0:
            result["length_ratio"] = 1.0

        # Token-level similarity (Jaccard on HTML structural tokens)
        resp_tokens = set(_tokenize_html(body))
        bl_tokens = bl["token_set"]
        if bl_tokens or resp_tokens:
            intersection = bl_tokens & resp_tokens
            union = bl_tokens | resp_tokens
            result["token_similarity"] = round(len(intersection) / len(union), 3) if union else 0.0
        else:
            result["token_similarity"] = 1.0  # both empty

        # Body text similarity (SequenceMatcher on truncated bodies for speed)
        max_cmp = 5000
        body_a = self._samples[0]["body"][:max_cmp] if self._samples else ""
        body_b = body[:max_cmp]
        if body_a and body_b:
            result["body_similarity"] = round(
                SequenceMatcher(None, body_a, body_b).ratio(), 3)
        elif not body_a and not body_b:
            result["body_similarity"] = 1.0

        # Composite similarity score (weighted)
        w_body = 0.4
        w_token = 0.3
        w_length = 0.2
        w_status = 0.1
        sim = (w_body * result["body_similarity"] +
               w_token * result["token_similarity"] +
               w_length * result["length_ratio"] +
               w_status * (1.0 if result["status_match"] else 0.0))
        result["similarity"] = round(sim, 3)

        # Verdict thresholds
        if sim >= 0.90:
            result["verdict"] = "identical"
            result["similar"] = True
        elif sim >= 0.70:
            result["verdict"] = "similar"
            result["similar"] = True
        elif _is_block_page(body):
            result["verdict"] = "block_page"
        else:
            result["verdict"] = "different"

        # FP indicators
        if result["similar"] and not _is_block_page(body):
            result["fp_indicators"].append("response_similar_to_baseline")
        if bl["stable_body"] and result["body_similarity"] > 0.95:
            result["fp_indicators"].append("near_identical_to_stable_baseline")
        if result["length_ratio"] > 0.95 and result["status_match"]:
            result["fp_indicators"].append("same_size_same_status")
        if len(body) < 50 and bl_len > 200:
            result["fp_indicators"].append("empty_response")

        return result

    # ── Batch filtering ───────────────────────────────────────────────

    def filter_noise(self, results: List[Dict],
                     fp_threshold: int = 60) -> Tuple[List[Dict], List[Dict]]:
        """Split test results into confirmed findings vs noise.

        Args:
            results: List of test_payload result dicts (must have 'fp_score').
            fp_threshold: FP score above which results are classified as noise.

        Returns:
            (confirmed, noise) tuple of result lists.
        """
        confirmed = []
        noise = []
        for r in results:
            if r.get("fp_score", 0) >= fp_threshold:
                noise.append(r)
            else:
                confirmed.append(r)
        return confirmed, noise


# ── Module-level helpers ──────────────────────────────────────────────

_TAG_RE = re.compile(r"</?([a-zA-Z][a-zA-Z0-9]*)")


def _tokenize_html(body: str) -> List[str]:
    """Extract structural HTML tokens (tag names) from a response body."""
    return _TAG_RE.findall(body[:10000])


_BLOCK_SIGNATURES = (
    "access denied", "blocked", "forbidden", "web application firewall",
    "captcha", "challenge", "error code:", "request blocked",
    "mod_security", "modsecurity", "attention required",
    "the requested url was rejected", "incident id",
)


def _is_block_page(body: str) -> bool:
    """Check if a response body contains WAF block page signatures."""
    lower = body.lower()
    return any(sig in lower for sig in _BLOCK_SIGNATURES)


def diff_responses(baseline_body: str, test_body: str) -> Dict[str, Any]:
    """Quick one-shot diff between two response bodies.

    Returns similarity metrics without needing a full ResponseDiffer instance.
    """
    if not baseline_body and not test_body:
        return {"similarity": 1.0, "identical": True}

    body_hash_a = hashlib.md5(baseline_body.encode("utf-8", errors="replace")).hexdigest()
    body_hash_b = hashlib.md5(test_body.encode("utf-8", errors="replace")).hexdigest()

    if body_hash_a == body_hash_b:
        return {"similarity": 1.0, "identical": True}

    max_cmp = 5000
    body_sim = SequenceMatcher(None, baseline_body[:max_cmp], test_body[:max_cmp]).ratio()

    tokens_a = set(_tokenize_html(baseline_body))
    tokens_b = set(_tokenize_html(test_body))
    union = tokens_a | tokens_b
    token_sim = len(tokens_a & tokens_b) / len(union) if union else 1.0

    len_a, len_b = len(baseline_body), len(test_body)
    len_ratio = min(len_a, len_b) / max(len_a, len_b) if max(len_a, len_b) > 0 else 1.0

    overall = 0.4 * body_sim + 0.3 * token_sim + 0.3 * len_ratio

    return {
        "similarity": round(overall, 3),
        "identical": False,
        "body_similarity": round(body_sim, 3),
        "token_similarity": round(token_sim, 3),
        "length_ratio": round(len_ratio, 3),
        "is_block_page": _is_block_page(test_body),
    }
