"""Risk scoring — professional classification of findings.

Uses conservative wording: "not observed during configured test" rather than
"vulnerability definitely exists".
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from rlcheck.detectors.rate_limit import RateLimitResult
from rlcheck.detectors.lockout import LockoutResult
from rlcheck.detectors.captcha import CaptchaResult
from rlcheck.detectors.otp import OTPDetectionResult


@dataclass
class Finding:
    """A single classified finding."""
    category: str = ""           # e.g. "RATE LIMITING", "OTP LOCKOUT"
    status: str = ""             # DETECTED / NOT DETECTED / POSSIBLE
    confidence: str = "LOW"
    risk_summary: str = ""
    recommendation: str = ""
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "status": self.status,
            "confidence": self.confidence,
            "risk_summary": self.risk_summary,
            "recommendation": self.recommendation,
            "evidence": self.evidence,
        }


@dataclass
class AssessmentScore:
    """Aggregated scoring for a full assessment run."""
    findings: List[Finding] = field(default_factory=list)
    overall_confidence: str = "LOW"
    flow_description: str = ""

    def to_dict(self) -> dict:
        return {
            "findings": [f.to_dict() for f in self.findings],
            "overall_confidence": self.overall_confidence,
            "flow_description": self.flow_description,
        }


def score_assessment(
    *,
    rate_limit: Optional[RateLimitResult] = None,
    lockout: Optional[LockoutResult] = None,
    captcha: Optional[CaptchaResult] = None,
    otp_detection: Optional[OTPDetectionResult] = None,
    login_rate_limit: Optional[RateLimitResult] = None,
) -> AssessmentScore:
    """Build findings from detector results."""
    score = AssessmentScore()

    # ── Login rate-limit ────────────────────────────────────────────────────
    if login_rate_limit is not None:
        f = Finding(category="LOGIN RATE LIMITING")
        if login_rate_limit.detected:
            f.status = "DETECTED"
            f.confidence = login_rate_limit.confidence
            f.risk_summary = "Login rate limiting was observed during the configured test."
            f.recommendation = "Verify that the rate limiting is sufficiently restrictive."
        else:
            f.status = "NOT DETECTED"
            f.confidence = login_rate_limit.confidence
            f.risk_summary = (
                "Login rate limiting was not observed during the configured test. "
                "Repeated authentication attempts may not be sufficiently restricted."
            )
            f.recommendation = (
                "Implement server-side throttling, progressive delays, "
                "temporary lockout, or equivalent anti-automation controls "
                "for the login endpoint."
            )
        f.evidence = login_rate_limit.evidence
        score.findings.append(f)

    # ── OTP rate-limit ──────────────────────────────────────────────────────
    if rate_limit is not None:
        f = Finding(category="OTP RATE LIMITING")
        if rate_limit.detected:
            f.status = "DETECTED"
            f.confidence = rate_limit.confidence
            f.risk_summary = "OTP rate limiting was observed during the configured test."
            f.recommendation = "Verify that the rate limiting is sufficiently restrictive."
            if rate_limit.retry_after:
                f.risk_summary += f" Retry-After: {rate_limit.retry_after}s."
        else:
            f.status = "NOT DETECTED"
            f.confidence = rate_limit.confidence
            f.risk_summary = (
                "OTP rate limiting was not observed during the configured test. "
                "Insufficient OTP attempt throttling may allow repeated submissions."
            )
            f.recommendation = (
                "Implement server-side OTP attempt throttling, progressive delays, "
                "or temporary verification lockout."
            )
        f.evidence = rate_limit.evidence
        score.findings.append(f)

    # ── Lockout ─────────────────────────────────────────────────────────────
    if lockout is not None:
        f = Finding(category="ACCOUNT/SESSION LOCKOUT")
        if lockout.detected:
            f.status = "DETECTED"
            f.confidence = lockout.confidence
            f.risk_summary = "Temporary lockout was observed after repeated failed attempts."
            f.recommendation = "Verify lockout duration and reset behaviour are appropriate."
            if lockout.duration_hint:
                f.risk_summary += f" Duration hint: {lockout.duration_hint}."
        elif lockout.possible:
            f.status = "POSSIBLE"
            f.confidence = lockout.confidence
            f.risk_summary = (
                "Behavioural changes suggest a possible lockout mechanism, "
                "but conclusive evidence was not obtained during the configured test."
            )
            f.recommendation = "Investigate further with extended testing."
        else:
            f.status = "NOT DETECTED"
            f.confidence = lockout.confidence
            f.risk_summary = (
                "Account or session lockout was not observed during the configured test."
            )
            f.recommendation = (
                "Consider implementing temporary account lockout after "
                "a threshold of failed authentication attempts."
            )
        f.evidence = lockout.evidence
        score.findings.append(f)

    # ── CAPTCHA ─────────────────────────────────────────────────────────────
    if captcha is not None:
        f = Finding(category="CAPTCHA / ANTI-AUTOMATION")
        if captcha.detected:
            f.status = "DETECTED"
            f.confidence = "HIGH"
            f.risk_summary = (
                f"{captcha.captcha_type or 'Anti-automation challenge'} was detected. "
                f"Testing was stopped at attempt {captcha.detected_at_attempt}."
            )
            f.recommendation = "Anti-automation control is in place."
        else:
            f.status = "NOT DETECTED"
            f.confidence = "MEDIUM"
            f.risk_summary = (
                "No CAPTCHA or anti-automation challenge was observed "
                "during the configured test."
            )
            f.recommendation = (
                "Consider adding CAPTCHA or anti-automation challenges "
                "after repeated failed attempts."
            )
        f.evidence = captcha.evidence
        score.findings.append(f)

    # ── OTP detection ───────────────────────────────────────────────────────
    if otp_detection is not None:
        f = Finding(category="OTP / MFA IMPLEMENTATION")
        if otp_detection.detected:
            f.status = "DETECTED"
            f.confidence = otp_detection.confidence
            f.risk_summary = (
                f"OTP verification page detected (field: {otp_detection.otp_field})."
            )
            f.recommendation = (
                "OTP/MFA is implemented. Ensure OTP validity period, "
                "attempt limits, and re-use prevention are enforced."
            )
        else:
            f.status = "NOT DETECTED"
            f.confidence = otp_detection.confidence
            f.risk_summary = (
                "No OTP / MFA verification was detected after login."
            )
            f.recommendation = (
                "Consider implementing multi-factor authentication."
            )
        f.evidence = otp_detection.evidence
        score.findings.append(f)

    # ── Overall confidence ──────────────────────────────────────────────────
    confidences = [f.confidence for f in score.findings]
    if "HIGH" in confidences:
        score.overall_confidence = "HIGH"
    elif "MEDIUM" in confidences:
        score.overall_confidence = "MEDIUM"
    else:
        score.overall_confidence = "LOW"

    return score
