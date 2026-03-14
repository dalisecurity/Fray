#!/usr/bin/env python3
"""
Fray Challenge Solver — bypass WAF challenges (Cloudflare, reCAPTCHA, hCaptcha).

Supports:
  - Cloudflare JS Challenge ("checking your browser") → cf_clearance cookie
  - Cloudflare Turnstile → click widget + extract token
  - reCAPTCHA v2 → audio challenge + speech-to-text
  - hCaptcha → manual solve once, reuse session token
  - Auto-detection: detect challenge type → pick solver

Requires: pip install playwright && playwright install chromium
Optional: pip install openai-whisper (for reCAPTCHA audio solver)

Usage:
    from fray.challenge_solver import ChallengeSolver
    solver = ChallengeSolver("https://target.com")
    result = solver.solve()
    cookies = result.cookies  # Pass to WAFTester
"""

import json
import re
import time
import tempfile
import os
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field


# ── Challenge Types ───────────────────────────────────────────────────────

class ChallengeType:
    NONE = "none"
    CF_JS = "cloudflare_js"          # "Checking your browser" interstitial
    CF_TURNSTILE = "cloudflare_turnstile"  # Turnstile widget
    RECAPTCHA_V2 = "recaptcha_v2"    # reCAPTCHA v2 checkbox/image
    RECAPTCHA_V3 = "recaptcha_v3"    # reCAPTCHA v3 invisible (score-based)
    HCAPTCHA = "hcaptcha"            # hCaptcha widget
    DATADOME = "datadome"            # DataDome interstitial
    AKAMAI = "akamai_bot_manager"    # Akamai Bot Manager
    UNKNOWN = "unknown"


@dataclass
class SolveResult:
    """Result of a challenge solve attempt."""
    success: bool = False
    challenge_type: str = ChallengeType.NONE
    cookies: Dict[str, str] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    token: str = ""
    user_agent: str = ""
    elapsed_s: float = 0.0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "success": self.success,
            "challenge_type": self.challenge_type,
            "cookies": self.cookies,
            "token": self.token[:50] + "..." if len(self.token) > 50 else self.token,
            "user_agent": self.user_agent,
            "elapsed_s": round(self.elapsed_s, 1),
            "error": self.error,
        }


# ── Stealth Patches ──────────────────────────────────────────────────────

_STEALTH_JS = """
// Remove webdriver flag
Object.defineProperty(navigator, 'webdriver', { get: () => false });

// Chrome runtime
window.chrome = { runtime: {}, loadTimes: function(){}, csi: function(){} };

// Plugins array (real browsers have 3-5 plugins)
Object.defineProperty(navigator, 'plugins', {
    get: () => [
        { name: 'Chrome PDF Plugin', filename: 'internal-pdf-viewer' },
        { name: 'Chrome PDF Viewer', filename: 'mhjfbmdgcfjbbpaeojofohoefgiehjai' },
        { name: 'Native Client', filename: 'internal-nacl-plugin' },
    ]
});

// Languages
Object.defineProperty(navigator, 'languages', {
    get: () => ['en-US', 'en']
});

// Platform
Object.defineProperty(navigator, 'platform', {
    get: () => 'Win32'
});

// Permissions API — mimic real browser
const originalQuery = window.navigator.permissions.query;
window.navigator.permissions.query = (parameters) =>
    parameters.name === 'notifications'
        ? Promise.resolve({ state: Notification.permission })
        : originalQuery(parameters);

// WebGL vendor/renderer (avoid headless detection)
const getParameter = WebGLRenderingContext.prototype.getParameter;
WebGLRenderingContext.prototype.getParameter = function(parameter) {
    if (parameter === 37445) return 'Intel Inc.';
    if (parameter === 37446) return 'Intel Iris OpenGL Engine';
    return getParameter.apply(this, arguments);
};

// Connection rtt (headless has 0)
Object.defineProperty(navigator, 'connection', {
    get: () => ({ rtt: 50, downlink: 10, effectiveType: '4g', saveData: false })
});

// Remove headless indicators from user agent
if (navigator.userAgent.includes('Headless')) {
    Object.defineProperty(navigator, 'userAgent', {
        get: () => navigator.userAgent.replace('Headless', '')
    });
}
"""

# Realistic viewport + screen dimensions
_STEALTH_VIEWPORT = {"width": 1920, "height": 1080}
_STEALTH_SCREEN = {"width": 1920, "height": 1080}
_STEALTH_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/125.0.0.0 Safari/537.36"
)


def _apply_stealth(context):
    """Apply stealth patches to a Playwright browser context."""
    context.add_init_script(_STEALTH_JS)


# ── Challenge Detection ──────────────────────────────────────────────────

# Detection patterns — (body_pattern, header_pattern, challenge_type)
_DETECT_PATTERNS = [
    # Cloudflare JS Challenge
    (r'Checking if the site connection is secure|Just a moment\.\.\.|cf-challenge-running',
     r'cf-mitigated.*challenge|server.*cloudflare',
     ChallengeType.CF_JS),
    # Cloudflare Turnstile
    (r'challenges\.cloudflare\.com/turnstile|cf-turnstile|turnstile-widget',
     None,
     ChallengeType.CF_TURNSTILE),
    # reCAPTCHA v3 (invisible) — must be checked BEFORE v2 (more specific pattern)
    (r'recaptcha/api\.js\?render=|grecaptcha\.execute\s*\(\s*[\'"][^\'"]+[\'"]\s*,',
     None,
     ChallengeType.RECAPTCHA_V3),
    # reCAPTCHA v2
    (r'google\.com/recaptcha/api\.js|g-recaptcha|grecaptcha\.execute',
     None,
     ChallengeType.RECAPTCHA_V2),
    # hCaptcha
    (r'hcaptcha\.com/1/api\.js|h-captcha|hcaptcha-response',
     None,
     ChallengeType.HCAPTCHA),
    # DataDome
    (r'datadome\.co/captcha|dd\.js|DataDome',
     r'x-datadome|set-cookie.*datadome',
     ChallengeType.DATADOME),
    # Akamai Bot Manager
    (r'_abck|akamai.*bot|ak_bmsc',
     r'x-akamai-|akamai',
     ChallengeType.AKAMAI),
]


def detect_challenge(body: str, headers: Dict[str, str] = None,
                     status: int = 0) -> str:
    """Detect challenge type from response body and headers.

    Args:
        body: Response body HTML.
        headers: Response headers (lowercase keys).
        status: HTTP status code.

    Returns:
        ChallengeType string.
    """
    if not body and status not in (403, 503):
        return ChallengeType.NONE

    headers = headers or {}
    headers_str = " ".join(f"{k}: {v}" for k, v in headers.items())

    for body_pat, hdr_pat, ctype in _DETECT_PATTERNS:
        body_match = re.search(body_pat, body, re.I) if body_pat else False
        hdr_match = re.search(hdr_pat, headers_str, re.I) if hdr_pat else False
        if body_match or hdr_match:
            return ctype

    # Cloudflare 503 with challenge
    if status == 503 and "cloudflare" in headers.get("server", "").lower():
        return ChallengeType.CF_JS

    # Generic 403 with challenge indicators
    if status == 403 and any(k in body.lower() for k in ["challenge", "captcha", "verify"]):
        return ChallengeType.UNKNOWN

    return ChallengeType.NONE


# ── Solvers ──────────────────────────────────────────────────────────────

class ChallengeSolver:
    """Unified challenge solver — detects and solves WAF challenges.

    Usage:
        solver = ChallengeSolver("https://target.com")
        result = solver.solve()
        if result.success:
            # Use result.cookies with WAFTester
            pass
    """

    def __init__(self, target: str, timeout: int = 30, verbose: bool = False,
                 headless: bool = True):
        self.target = target
        self.timeout = timeout
        self.verbose = verbose
        self.headless = headless

    def solve(self, challenge_type: str = None) -> SolveResult:
        """Detect and solve the challenge.

        Args:
            challenge_type: Force a specific challenge type, or auto-detect.

        Returns:
            SolveResult with cookies/token on success.
        """
        t0 = time.monotonic()
        result = SolveResult()

        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            result.error = ("Playwright required for challenge solving. "
                            "Install: pip install playwright && playwright install chromium")
            return result

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(
                    headless=self.headless,
                    args=[
                        "--disable-blink-features=AutomationControlled",
                        "--disable-features=IsolateOrigins,site-per-process",
                        "--no-sandbox",
                    ],
                )
                context = browser.new_context(
                    viewport=_STEALTH_VIEWPORT,
                    screen=_STEALTH_SCREEN,
                    user_agent=_STEALTH_UA,
                    locale="en-US",
                    timezone_id="America/New_York",
                    color_scheme="light",
                )
                _apply_stealth(context)
                page = context.new_page()

                # Navigate to target
                resp = page.goto(self.target, wait_until="domcontentloaded",
                                 timeout=self.timeout * 1000)

                status = resp.status if resp else 0
                body = page.content()
                resp_headers = {k.lower(): v for k, v in (resp.all_headers().items() if resp else {})}

                # Detect challenge type
                if not challenge_type:
                    challenge_type = detect_challenge(body, resp_headers, status)

                result.challenge_type = challenge_type
                result.user_agent = _STEALTH_UA

                if self.verbose:
                    print(f"  Challenge detected: {challenge_type}")

                # Dispatch to solver
                if challenge_type == ChallengeType.NONE:
                    result.success = True
                    result.cookies = self._extract_cookies(context)
                elif challenge_type == ChallengeType.CF_JS:
                    result = self._solve_cf_js(page, context, result)
                elif challenge_type == ChallengeType.CF_TURNSTILE:
                    result = self._solve_cf_turnstile(page, context, result)
                elif challenge_type == ChallengeType.RECAPTCHA_V2:
                    result = self._solve_recaptcha_v2(page, context, result)
                elif challenge_type == ChallengeType.HCAPTCHA:
                    result = self._solve_hcaptcha(page, context, result)
                else:
                    # For unsupported types, try waiting (JS challenge pattern)
                    result = self._solve_generic_wait(page, context, result)

                browser.close()

        except Exception as e:
            result.error = str(e)

        result.elapsed_s = time.monotonic() - t0
        return result

    def _extract_cookies(self, context) -> Dict[str, str]:
        """Extract all cookies from the browser context."""
        cookies = {}
        for c in context.cookies():
            cookies[c["name"]] = c["value"]
        return cookies

    def _solve_cf_js(self, page, context, result: SolveResult) -> SolveResult:
        """Solve Cloudflare JS Challenge (checking your browser).

        Strategy: Just wait — Cloudflare's JS challenge auto-solves with a real
        browser. The stealth patches prevent bot detection. After 3-8 seconds,
        the page redirects and sets cf_clearance cookie.
        """
        result.challenge_type = ChallengeType.CF_JS

        if self.verbose:
            print(f"  Waiting for Cloudflare JS challenge to auto-solve...")

        # Wait for challenge to complete (redirect or cookie)
        max_wait = min(self.timeout, 20)
        for _ in range(max_wait * 2):  # Check every 500ms
            time.sleep(0.5)
            cookies = self._extract_cookies(context)
            if "cf_clearance" in cookies:
                result.success = True
                result.cookies = cookies
                if self.verbose:
                    print(f"  ✔ cf_clearance cookie obtained")
                return result

            # Check if page has moved past challenge
            try:
                body = page.content()
                if not re.search(r'Just a moment|cf-challenge-running|Checking', body, re.I):
                    result.success = True
                    result.cookies = cookies
                    return result
            except Exception:
                pass

        result.error = "Cloudflare JS challenge did not resolve within timeout"
        result.cookies = self._extract_cookies(context)
        return result

    def _solve_cf_turnstile(self, page, context, result: SolveResult) -> SolveResult:
        """Solve Cloudflare Turnstile widget.

        Strategy: Find the Turnstile iframe, click it, wait for token.
        Turnstile is designed to auto-pass for real browsers — stealth patches
        make Playwright look real enough.
        """
        result.challenge_type = ChallengeType.CF_TURNSTILE

        if self.verbose:
            print(f"  Solving Cloudflare Turnstile...")

        try:
            # Wait for Turnstile widget to load
            page.wait_for_selector(
                'iframe[src*="challenges.cloudflare.com/turnstile"], '
                '[class*="cf-turnstile"], '
                '#cf-turnstile-response',
                timeout=10000,
            )
            time.sleep(1.5)  # Let widget fully render

            # Try clicking the Turnstile checkbox inside iframe
            frames = page.frames
            for frame in frames:
                if "challenges.cloudflare.com" in (frame.url or ""):
                    try:
                        # Click the checkbox
                        checkbox = frame.query_selector(
                            'input[type="checkbox"], .ctp-checkbox-label, '
                            '[id*="challenge"], label'
                        )
                        if checkbox:
                            checkbox.click()
                            time.sleep(2)
                    except Exception:
                        pass
                    break

            # Also try direct click on the Turnstile container
            try:
                widget = page.query_selector(
                    '[class*="cf-turnstile"], [data-sitekey]'
                )
                if widget:
                    box = widget.bounding_box()
                    if box:
                        # Click center of widget
                        page.mouse.click(
                            box["x"] + box["width"] / 2,
                            box["y"] + box["height"] / 2,
                        )
                        time.sleep(2)
            except Exception:
                pass

            # Wait for token to appear
            for _ in range(20):
                time.sleep(0.5)
                try:
                    token = page.evaluate(
                        "() => {"
                        "  const el = document.querySelector("
                        "    '[name=\"cf-turnstile-response\"], "
                        "    [name=\"g-recaptcha-response\"], "
                        "    input[name*=\"turnstile\"]'"
                        "  );"
                        "  return el ? el.value : '';"
                        "}"
                    )
                    if token:
                        result.success = True
                        result.token = token
                        result.cookies = self._extract_cookies(context)
                        if self.verbose:
                            print(f"  ✔ Turnstile token: {token[:30]}...")
                        return result
                except Exception:
                    pass

                # Check if cf_clearance appeared
                cookies = self._extract_cookies(context)
                if "cf_clearance" in cookies:
                    result.success = True
                    result.cookies = cookies
                    return result

        except Exception as e:
            result.error = f"Turnstile solver error: {e}"

        result.cookies = self._extract_cookies(context)
        return result

    def _solve_recaptcha_v2(self, page, context, result: SolveResult) -> SolveResult:
        """Solve reCAPTCHA v2 via audio challenge + speech-to-text.

        Strategy:
        1. Click "I'm not a robot" checkbox
        2. If image challenge appears, switch to audio
        3. Download audio, transcribe with Whisper
        4. Submit text answer
        """
        result.challenge_type = ChallengeType.RECAPTCHA_V2

        if self.verbose:
            print(f"  Solving reCAPTCHA v2 (audio method)...")

        try:
            # Find and click the reCAPTCHA iframe checkbox
            page.wait_for_selector(
                'iframe[src*="recaptcha/api2/anchor"], '
                'iframe[src*="recaptcha/enterprise/anchor"]',
                timeout=10000,
            )
            time.sleep(1)

            # Click the checkbox in the anchor iframe
            for frame in page.frames:
                if "recaptcha" in (frame.url or "") and "anchor" in (frame.url or ""):
                    try:
                        checkbox = frame.wait_for_selector(
                            '#recaptcha-anchor, .recaptcha-checkbox',
                            timeout=5000,
                        )
                        if checkbox:
                            checkbox.click()
                            time.sleep(2)
                    except Exception:
                        pass
                    break

            # Check if solved immediately (lucky)
            token = self._get_recaptcha_token(page)
            if token:
                result.success = True
                result.token = token
                result.cookies = self._extract_cookies(context)
                return result

            # Switch to audio challenge
            for frame in page.frames:
                if "recaptcha" in (frame.url or "") and "bframe" in (frame.url or ""):
                    try:
                        audio_btn = frame.query_selector(
                            '#recaptcha-audio-button, .rc-button-audio'
                        )
                        if audio_btn:
                            audio_btn.click()
                            time.sleep(2)

                        # Get audio URL
                        audio_src = frame.evaluate(
                            "() => {"
                            "  const el = document.querySelector("
                            "    '#audio-source, .rc-audiochallenge-tdownload-link a'"
                            "  );"
                            "  return el ? (el.src || el.href) : '';"
                            "}"
                        )

                        if audio_src:
                            # Transcribe audio
                            transcript = self._transcribe_audio(audio_src)
                            if transcript:
                                # Type the answer
                                input_el = frame.query_selector(
                                    '#audio-response, input[id*="audio-response"]'
                                )
                                if input_el:
                                    input_el.fill(transcript)
                                    time.sleep(0.5)
                                    # Click verify
                                    verify_btn = frame.query_selector(
                                        '#recaptcha-verify-button, .rc-button-default'
                                    )
                                    if verify_btn:
                                        verify_btn.click()
                                        time.sleep(3)
                    except Exception as e:
                        if self.verbose:
                            print(f"  ⚠ reCAPTCHA audio solver error: {e}")
                    break

            # Check for token
            token = self._get_recaptcha_token(page)
            if token:
                result.success = True
                result.token = token
                result.cookies = self._extract_cookies(context)
                if self.verbose:
                    print(f"  ✔ reCAPTCHA solved via audio")
                return result

            result.error = "reCAPTCHA audio solver could not extract token"

        except Exception as e:
            result.error = f"reCAPTCHA solver error: {e}"

        result.cookies = self._extract_cookies(context)
        return result

    def _get_recaptcha_token(self, page) -> str:
        """Extract reCAPTCHA response token from the page."""
        try:
            return page.evaluate(
                "() => {"
                "  const el = document.querySelector("
                "    '#g-recaptcha-response, [name=\"g-recaptcha-response\"], "
                "    textarea[id*=\"g-recaptcha-response\"]'"
                "  );"
                "  return el ? el.value : '';"
                "}"
            )
        except Exception:
            return ""

    def _transcribe_audio(self, audio_url: str) -> str:
        """Download and transcribe reCAPTCHA audio challenge.

        Uses OpenAI Whisper (local) for speech-to-text.
        Falls back to Google Speech API if whisper unavailable.
        """
        import urllib.request

        # Download audio
        try:
            tmp = tempfile.NamedTemporaryFile(suffix=".mp3", delete=False)
            urllib.request.urlretrieve(audio_url, tmp.name)
            tmp.close()
        except Exception:
            return ""

        transcript = ""

        # Try Whisper first (local, no API key needed)
        try:
            import whisper
            model = whisper.load_model("base")
            result = model.transcribe(tmp.name, language="en")
            transcript = result.get("text", "").strip().lower()
            # Clean up common transcription artifacts
            transcript = re.sub(r'[^a-z0-9\s]', '', transcript).strip()
        except ImportError:
            pass
        except Exception:
            pass

        # Fallback: Google Speech Recognition
        if not transcript:
            try:
                import speech_recognition as sr
                recognizer = sr.Recognizer()
                # Convert mp3 to wav if needed
                wav_path = tmp.name.replace(".mp3", ".wav")
                try:
                    import subprocess
                    subprocess.run(
                        ["ffmpeg", "-i", tmp.name, "-ar", "16000", "-ac", "1",
                         wav_path, "-y"],
                        capture_output=True, timeout=10,
                    )
                    with sr.AudioFile(wav_path) as source:
                        audio = recognizer.record(source)
                    transcript = recognizer.recognize_google(audio).lower()
                except Exception:
                    pass
                finally:
                    if os.path.exists(wav_path):
                        os.unlink(wav_path)
            except ImportError:
                pass

        # Cleanup
        try:
            os.unlink(tmp.name)
        except Exception:
            pass

        return transcript

    def _solve_hcaptcha(self, page, context, result: SolveResult) -> SolveResult:
        """Solve hCaptcha — manual interactive mode or session reuse.

        hCaptcha is harder to auto-solve than Turnstile. Strategy:
        1. If headless=False, let user solve manually
        2. If a saved hcaptcha session exists, reuse it
        3. Try clicking the checkbox (sometimes auto-passes)
        """
        result.challenge_type = ChallengeType.HCAPTCHA

        if self.verbose:
            print(f"  Attempting hCaptcha bypass...")

        # Check for saved session
        session_path = os.path.expanduser("~/.fray/hcaptcha_session.json")
        if os.path.exists(session_path):
            try:
                data = json.loads(open(session_path).read())
                if data.get("cookies") and time.time() - data.get("timestamp", 0) < 3600:
                    result.success = True
                    result.cookies = data["cookies"]
                    result.token = data.get("token", "")
                    if self.verbose:
                        print(f"  ✔ Reusing saved hCaptcha session")
                    return result
            except Exception:
                pass

        try:
            # Wait for hCaptcha iframe
            page.wait_for_selector(
                'iframe[src*="hcaptcha.com"], [data-hcaptcha-widget-id]',
                timeout=10000,
            )
            time.sleep(1.5)

            # Click the checkbox in the hCaptcha iframe
            for frame in page.frames:
                if "hcaptcha.com" in (frame.url or "") and "checkbox" in (frame.url or ""):
                    try:
                        checkbox = frame.query_selector('#checkbox, .check')
                        if checkbox:
                            checkbox.click()
                            time.sleep(3)
                    except Exception:
                        pass
                    break

            # Check if auto-passed
            token = page.evaluate(
                "() => {"
                "  const el = document.querySelector("
                "    '[name=\"h-captcha-response\"], "
                "    [name=\"g-recaptcha-response\"]'"
                "  );"
                "  return el ? el.value : '';"
                "}"
            )
            if token:
                result.success = True
                result.token = token
                result.cookies = self._extract_cookies(context)
                # Save session for reuse
                self._save_hcaptcha_session(result.cookies, token)
                if self.verbose:
                    print(f"  ✔ hCaptcha auto-passed")
                return result

            # If not headless, wait for user to solve
            if not self.headless:
                if self.verbose:
                    print(f"  ⏳ Waiting for manual hCaptcha solve (browser is visible)...")
                for _ in range(60):  # Wait up to 30s
                    time.sleep(0.5)
                    token = page.evaluate(
                        "() => {"
                        "  const el = document.querySelector("
                        "    '[name=\"h-captcha-response\"]'"
                        "  );"
                        "  return el ? el.value : '';"
                        "}"
                    )
                    if token:
                        result.success = True
                        result.token = token
                        result.cookies = self._extract_cookies(context)
                        self._save_hcaptcha_session(result.cookies, token)
                        if self.verbose:
                            print(f"  ✔ hCaptcha solved manually")
                        return result

            result.error = "hCaptcha requires manual solve (use --no-headless)"

        except Exception as e:
            result.error = f"hCaptcha solver error: {e}"

        result.cookies = self._extract_cookies(context)
        return result

    def _save_hcaptcha_session(self, cookies: Dict, token: str):
        """Save hCaptcha session for reuse."""
        session_dir = os.path.expanduser("~/.fray")
        os.makedirs(session_dir, exist_ok=True)
        session_path = os.path.join(session_dir, "hcaptcha_session.json")
        try:
            with open(session_path, "w") as f:
                json.dump({
                    "cookies": cookies,
                    "token": token,
                    "timestamp": time.time(),
                }, f)
        except Exception:
            pass

    def _solve_generic_wait(self, page, context, result: SolveResult) -> SolveResult:
        """Generic solver: wait for JS challenge to auto-resolve.

        Many WAF challenges (Cloudflare, Akamai, DataDome) auto-solve
        when they see a real browser with proper JS execution.
        """
        if self.verbose:
            print(f"  Generic challenge wait ({result.challenge_type})...")

        max_wait = min(self.timeout, 15)
        initial_url = page.url

        for _ in range(max_wait * 2):
            time.sleep(0.5)
            cookies = self._extract_cookies(context)

            # Check for common success indicators
            if "cf_clearance" in cookies or "datadome" in str(cookies).lower():
                result.success = True
                result.cookies = cookies
                return result

            # Check if page navigated away from challenge
            if page.url != initial_url:
                result.success = True
                result.cookies = cookies
                return result

            # Check if challenge HTML is gone
            try:
                body = page.content()
                if not re.search(
                    r'challenge|captcha|checking.*browser|just a moment',
                    body, re.I
                ):
                    result.success = True
                    result.cookies = cookies
                    return result
            except Exception:
                pass

        result.error = f"Challenge did not auto-resolve within {max_wait}s"
        result.cookies = self._extract_cookies(context)
        return result


# ── Convenience Functions ────────────────────────────────────────────────

def solve_challenge(target: str, timeout: int = 30, verbose: bool = False,
                    headless: bool = True) -> SolveResult:
    """One-shot challenge solver — convenience function.

    Returns SolveResult with cookies/token.
    """
    return ChallengeSolver(target, timeout=timeout, verbose=verbose,
                           headless=headless).solve()


def extract_cf_clearance(target: str, timeout: int = 20,
                         verbose: bool = False) -> Dict[str, str]:
    """Extract Cloudflare cf_clearance cookie.

    Returns dict of cookies (empty if failed).
    """
    result = solve_challenge(target, timeout=timeout, verbose=verbose)
    return result.cookies if result.success else {}
