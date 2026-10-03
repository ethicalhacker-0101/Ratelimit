"""CAPTCHA / anti-automation challenge detection.

Detects reCAPTCHA, hCaptcha, Cloudflare Turnstile, and generic challenge pages
in HTTP responses.  The tool **never** attempts to bypass these challenges.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from rlcheck.engine.request_engine import RequestRecord

# HTML / JS markers for popular CAPTCHA systems
_CAPTCHA_MARKERS = [
    # reCAPTCHA
    re.compile(r"(g-recaptcha|grecaptcha|recaptcha|google\.com/recaptcha)", re.I),
    # hCaptcha
    re.compile(r"(h-captcha|hcaptcha|hcaptcha\.com)", re.I),
    # Cloudflare Turnstile
    re.compile(r"(cf-turnstile|challenges\.cloudflare\.com/turnstile)", re.I),
    # Generic
    re.compile(r"(captcha|challenge[-_]?page|bot[-_]?detect|are[-_]?you[-_]?human|"
               r"verify[-_]?you[-_]?are[-_]?human|proof[-_]?of[-_]?work)", re.I),
]

# Cloudflare / DDoS-protection pages
_CF_CHALLENGE = re.compile(
    r"(checking\s+your\s+browser|attention\s+required|"
    r"cloudflare|just\s+a\s+moment|enable\s+javascript\s+and\s+cookies)",
    re.IGNORECASE,
)


@dataclass
class CaptchaResult:
    """Outcome of CAPTCHA / anti-automation detection."""
    detected: bool = False
    captcha_type: Optional[str] = None    # reCAPTCHA / hCaptcha / Turnstile / Generic
    detected_at_attempt: Optional[int] = None
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "detected": self.detected,
            "captcha_type": self.captcha_type,
            "detected_at_attempt": self.detected_at_attempt,
            "evidence": self.evidence,
        }


def check_captcha_in_html(html: str) -> Optional[str]:
    """Return the CAPTCHA type name if detected in *html*, else ``None``."""
    for i, pattern in enumerate(_CAPTCHA_MARKERS):
        if pattern.search(html):
            if i == 0:
                return "reCAPTCHA"
            elif i == 1:
                return "hCaptcha"
            elif i == 2:
                return "Turnstile"
            else:
                return "Generic CAPTCHA"
    if _CF_CHALLENGE.search(html):
        return "Cloudflare Challenge"
    return None


def detect_captcha(records: List[RequestRecord], response_bodies: dict[int, str]) -> CaptchaResult:
    """Analyse responses for CAPTCHA / challenge indicators.

    Parameters
    ----------
    records : list[RequestRecord]
        Evidence records from the test run.
    response_bodies : dict[int, str]
        Mapping of ``attempt → response body text`` (only stored transiently for
        CAPTCHA scanning; not persisted).
    """
    result = CaptchaResult()

    for rec in records:
        body = response_bodies.get(rec.attempt, "")
        ctype = check_captcha_in_html(body)
        if ctype:
            result.detected = True
            result.captcha_type = ctype
            if result.detected_at_attempt is None:
                result.detected_at_attempt = rec.attempt
            result.evidence.append(
                f"Attempt {rec.attempt}: {ctype} detected in response"
            )

        if rec.challenge_detected:
            result.detected = True
            result.captcha_type = result.captcha_type or "Unknown Challenge"
            result.evidence.append(
                f"Attempt {rec.attempt}: Challenge flag set"
            )

    return result


def should_stop_for_captcha(html: str) -> bool:
    """Return ``True`` if a CAPTCHA / challenge was detected — testing must stop."""
    return check_captcha_in_html(html) is not None
