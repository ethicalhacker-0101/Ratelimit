from unittest.mock import MagicMock
import pytest

from rlcheck.engine.request_engine import RequestRecord
from rlcheck.detectors.rate_limit import (
    RateLimitResult,
    detect_rate_limit,
    should_stop_for_rate_limit,
)
from rlcheck.detectors.lockout import (
    LockoutResult,
    detect_lockout,
    should_stop_for_lockout,
)
from rlcheck.detectors.captcha import (
    CaptchaResult,
    check_captcha_in_html,
    detect_captcha,
    should_stop_for_captcha,
)
from rlcheck.detectors.otp import (
    OTPDetectionResult,
    evaluate_otp_detection,
)
from rlcheck.detectors.fingerprint import (
    ResponseFingerprint,
    build_fingerprint,
    fingerprints_changed,
    detect_fingerprint_shift,
)
from rlcheck.discovery.otp import OTPFormInfo


# ── Rate Limit Tests ─────────────────────────────────────────────────────────

def test_rate_limit_result_to_dict():
    res = RateLimitResult(
        detected=True,
        confidence="HIGH",
        trigger_attempt=3,
        retry_after="60",
        evidence=["HTTP 429 received"],
    )
    d = res.to_dict()
    assert d["detected"] is True
    assert d["confidence"] == "HIGH"
    assert d["trigger_attempt"] == 3
    assert d["retry_after"] == "60"
    assert "HTTP 429 received" in d["evidence"]


def test_detect_rate_limit_empty():
    res = detect_rate_limit([])
    assert res.detected is False
    assert res.confidence == "LOW"
    assert res.trigger_attempt is None
    assert len(res.evidence) == 0


def test_detect_rate_limit_status_code_429():
    records = [
        RequestRecord(attempt=1, status=200),
        RequestRecord(attempt=2, status=429),
        RequestRecord(attempt=3, status=429),
    ]
    res = detect_rate_limit(records)
    assert res.detected is True
    assert res.confidence == "HIGH"
    assert res.trigger_attempt == 2
    assert len(res.evidence) == 2


def test_detect_rate_limit_headers():
    records = [
        RequestRecord(
            attempt=1,
            status=200,
            rate_limit_headers={"retry-after": "30", "ratelimit-remaining": "0"},
        ),
    ]
    res = detect_rate_limit(records)
    assert res.detected is True
    assert res.retry_after == "30"


def test_should_stop_for_rate_limit():
    r1 = RequestRecord(status=200)
    assert should_stop_for_rate_limit(r1) is False

    r2 = RequestRecord(status=429)
    assert should_stop_for_rate_limit(r2) is True

    r3 = RequestRecord(status=200, rate_limit_headers={"retry-after": "10"})
    assert should_stop_for_rate_limit(r3) is True


# ── Lockout Tests ────────────────────────────────────────────────────────────

def test_lockout_result_to_dict():
    res = LockoutResult(
        detected=True,
        possible=True,
        confidence="HIGH",
        attempts_before_lockout=5,
        duration_hint="300 seconds",
        evidence=["HTTP 423 Locked"],
    )
    d = res.to_dict()
    assert d["detected"] is True
    assert d["attempts_before_lockout"] == 5
    assert d["duration_hint"] == "300 seconds"


def test_detect_lockout_empty():
    res = detect_lockout([])
    assert res.detected is False
    assert res.possible is False


def test_detect_lockout_423():
    records = [
        RequestRecord(attempt=1, status=200),
        RequestRecord(attempt=2, status=423),
        RequestRecord(attempt=3, status=423),
    ]
    res = detect_lockout(records)
    assert res.detected is True
    assert res.confidence == "HIGH"
    assert res.attempts_before_lockout == 2


def test_detect_lockout_status_shift():
    records = [
        RequestRecord(attempt=1, status=200),
        RequestRecord(attempt=2, status=200),
        RequestRecord(attempt=3, status=403),
        RequestRecord(attempt=4, status=403),
    ]
    res = detect_lockout(records)
    assert res.possible is True
    assert any("Status shifted" in ev for ev in res.evidence)


def test_should_stop_for_lockout():
    assert should_stop_for_lockout(RequestRecord(status=200)) is False
    assert should_stop_for_lockout(RequestRecord(status=423)) is True


# ── Captcha Tests ────────────────────────────────────────────────────────────

def test_check_captcha_in_html():
    assert check_captcha_in_html("<div class='g-recaptcha'></div>") == "reCAPTCHA"
    assert check_captcha_in_html("<script src='https://hcaptcha.com/1/api.js'></script>") == "hCaptcha"
    assert check_captcha_in_html("<div class='cf-turnstile'></div>") == "Turnstile"
    assert check_captcha_in_html("<div>Please solve the captcha to continue</div>") == "Generic CAPTCHA"
    assert check_captcha_in_html("<p>Just a moment... checking your browser</p>") == "Cloudflare Challenge"
    assert check_captcha_in_html("<html><body><h1>Welcome</h1></body></html>") is None


def test_detect_captcha_records():
    records = [
        RequestRecord(attempt=1, status=200),
        RequestRecord(attempt=2, status=200, challenge_detected=True),
    ]
    bodies = {
        1: "<html>Normal</html>",
        2: "<html><div class='g-recaptcha'></div></html>",
    }
    res = detect_captcha(records, bodies)
    assert res.detected is True
    assert res.captcha_type == "reCAPTCHA"
    assert res.detected_at_attempt == 2
    assert len(res.evidence) >= 1


def test_should_stop_for_captcha():
    assert should_stop_for_captcha("<html>Welcome</html>") is False
    assert should_stop_for_captcha("<html><div class='h-captcha'></div></html>") is True


# ── OTP Detector Tests ───────────────────────────────────────────────────────

def test_evaluate_otp_detection_none():
    res = evaluate_otp_detection(None)
    assert res.detected is False
    assert "No OTP form detected" in res.evidence[0]


def test_evaluate_otp_detection_valid():
    form_info = OTPFormInfo(
        action="https://example.com/verify",
        otp_field="otp_code",
        csrf_field="csrf_token",
        hidden_fields={"session_id": "xyz"},
        confidence="HIGH",
    )
    res = evaluate_otp_detection(form_info)
    assert res.detected is True
    assert res.otp_field == "otp_code"
    assert res.otp_endpoint == "https://example.com/verify"
    assert res.confidence == "HIGH"
    assert any("OTP field identified" in ev for ev in res.evidence)
    assert any("CSRF token present" in ev for ev in res.evidence)
    assert any("Hidden fields" in ev for ev in res.evidence)


# ── Fingerprint Detector Tests ───────────────────────────────────────────────

def test_build_fingerprint_and_equality():
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = b"<html>Success</html>"
    mock_resp.headers = {"content-type": "text/html"}

    fp1 = build_fingerprint(mock_resp)
    fp2 = build_fingerprint(mock_resp)

    assert fp1.status == 200
    assert fp1.body_length == len(b"<html>Success</html>")
    assert fp1 == fp2
    assert hash(fp1) == hash(fp2)

    d = fp1.to_dict()
    assert d["status"] == 200
    assert "body_hash" in d
    assert "combined" in d


def test_fingerprints_changed_and_shift():
    fp_a = ResponseFingerprint(status=200, combined_hash="hash_a")
    fp_b = ResponseFingerprint(status=429, combined_hash="hash_b")

    assert fingerprints_changed([]) is False
    assert fingerprints_changed([fp_a]) is False
    assert fingerprints_changed([fp_a, fp_a]) is False
    assert fingerprints_changed([fp_a, fp_b]) is True

    assert detect_fingerprint_shift([]) is None
    assert detect_fingerprint_shift([fp_a]) is None
    assert detect_fingerprint_shift([fp_a, fp_a]) is None
    assert detect_fingerprint_shift([fp_a, fp_a, fp_b]) == 2
