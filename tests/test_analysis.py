import pytest

from rlcheck.analysis.confidence import merge_confidences, confidence_from_signals
from rlcheck.analysis.timeline import Timeline, TimelineEvent
from rlcheck.analysis.scoring import Finding, AssessmentScore, score_assessment
from rlcheck.detectors.rate_limit import RateLimitResult
from rlcheck.detectors.lockout import LockoutResult
from rlcheck.detectors.captcha import CaptchaResult
from rlcheck.detectors.otp import OTPDetectionResult


# ── Confidence Tests ─────────────────────────────────────────────────────────

def test_merge_confidences():
    assert merge_confidences(["LOW", "MEDIUM"]) == "MEDIUM"
    assert merge_confidences(["MEDIUM", "HIGH", "LOW"]) == "HIGH"
    assert merge_confidences(["LOW"]) == "LOW"
    assert merge_confidences([]) == "LOW"


def test_confidence_from_signals():
    assert confidence_from_signals(0) == "LOW"
    assert confidence_from_signals(1) == "LOW"
    assert confidence_from_signals(2) == "MEDIUM"
    assert confidence_from_signals(3) == "MEDIUM"
    assert confidence_from_signals(4) == "HIGH"
    assert confidence_from_signals(10) == "HIGH"


# ── Timeline Tests ───────────────────────────────────────────────────────────

def test_timeline():
    tl = Timeline()
    assert len(tl) == 0
    tl.add("Initialized scanner", timestamp="12:00:00")
    tl.add("Sent request 1", timestamp="12:00:02")

    assert len(tl) == 2
    events = tl.to_list()
    assert events[0]["event"] == "Initialized scanner"
    assert events[0]["timestamp"] == "12:00:00"
    assert events[1]["event"] == "Sent request 1"
    assert events[1]["timestamp"] == "12:00:02"


# ── Scoring Tests ────────────────────────────────────────────────────────────

def test_finding_to_dict():
    f = Finding(
        category="LOGIN RATE LIMITING",
        status="DETECTED",
        confidence="HIGH",
        risk_summary="Rate limiting active",
        recommendation="Good configuration",
        evidence=["HTTP 429 received"],
    )
    d = f.to_dict()
    assert d["category"] == "LOGIN RATE LIMITING"
    assert d["status"] == "DETECTED"
    assert d["confidence"] == "HIGH"
    assert "HTTP 429 received" in d["evidence"]


def test_score_assessment_all_detected():
    login_rl = RateLimitResult(detected=True, confidence="HIGH", evidence=["429"])
    otp_rl = RateLimitResult(detected=True, confidence="HIGH", retry_after="60", evidence=["429"])
    lockout = LockoutResult(detected=True, confidence="HIGH", attempts_before_lockout=5)
    captcha = CaptchaResult(detected=True, captcha_type="reCAPTCHA")
    otp_det = OTPDetectionResult(detected=True, otp_field="code")

    score = score_assessment(
        login_rate_limit=login_rl,
        rate_limit=otp_rl,
        lockout=lockout,
        captcha=captcha,
        otp_detection=otp_det,
    )

    categories = [f.category for f in score.findings]
    assert "LOGIN RATE LIMITING" in categories
    assert "OTP RATE LIMITING" in categories
    assert "ACCOUNT/SESSION LOCKOUT" in categories
    assert "CAPTCHA / ANTI-AUTOMATION" in categories
    assert "OTP / MFA IMPLEMENTATION" in categories

    # Verify to_dict serialization
    score_dict = score.to_dict()
    assert len(score_dict["findings"]) == len(score.findings)


def test_score_assessment_none_detected():
    login_rl = RateLimitResult(detected=False, confidence="LOW")
    otp_rl = RateLimitResult(detected=False, confidence="LOW")
    lockout = LockoutResult(detected=False, possible=False, confidence="LOW")
    captcha = CaptchaResult(detected=False)

    score = score_assessment(
        login_rate_limit=login_rl,
        rate_limit=otp_rl,
        lockout=lockout,
        captcha=captcha,
    )

    for f in score.findings:
        assert f.status in ("NOT DETECTED", "NOT OBSERVED")
