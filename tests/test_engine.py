from unittest.mock import MagicMock, patch
import requests
import pytest

from rlcheck.engine.session import TrackedSession, SessionSnapshot, _sha256_short
from rlcheck.engine.request_engine import execute_request, RequestRecord
from rlcheck.engine.safety import SafetyConfig
from rlcheck.engine.auth_flow import (
    run_full_assessment,
    run_login_assessment,
    run_otp_assessment,
)


# ── Session Tests ────────────────────────────────────────────────────────────

def test_session_snapshot_differs_from():
    s1 = SessionSnapshot(cookies_hash="abc", session_ids={"sid": "123"})
    s2 = SessionSnapshot(cookies_hash="abc", session_ids={"sid": "123"})
    s3 = SessionSnapshot(cookies_hash="xyz", session_ids={"sid": "123"})
    s4 = SessionSnapshot(cookies_hash="abc", session_ids={"sid": "456"})

    assert s1.differs_from(s2) is False
    assert s1.differs_from(s3) is True
    assert s1.differs_from(s4) is True


def test_sha256_short():
    val = "test_cookie_value"
    res = _sha256_short(val)
    assert len(res) == 12
    assert isinstance(res, str)


def test_tracked_session_snapshots():
    ts = TrackedSession()
    # Mocking underlying requests.Session methods
    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.url = "https://example.com/login"
    mock_resp.history = []
    ts.session.get = MagicMock(return_value=mock_resp)

    # Initial snapshot
    snap1 = ts.take_snapshot()
    assert snap1.cookies_hash == ""

    # After request
    ts.get("https://example.com/login")
    assert len(ts.snapshots) == 1
    assert len(ts.redirect_chains) == 1


# ── Request Engine Tests ─────────────────────────────────────────────────────

def test_execute_request_get_success():
    mock_session = MagicMock()
    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 200
    mock_resp.content = b"Success response"
    mock_resp.url = "https://example.com/test"
    mock_resp.history = []
    mock_resp.headers = {
        "content-type": "text/html",
        "retry-after": "120",
        "strict-transport-security": "max-age=31536000",
    }
    mock_session.get.return_value = mock_resp

    rec = execute_request(mock_session, "GET", "https://example.com/test", attempt=1)

    assert rec.status == 200
    assert rec.attempt == 1
    assert rec.method == "GET"
    assert rec.url == "https://example.com/test"
    assert rec.response_size == len(b"Success response")
    assert rec.rate_limit_headers.get("retry-after") == "120"
    assert "strict-transport-security" in rec.selected_headers
    assert rec.fingerprint is not None

    d = rec.to_dict()
    assert d["status"] == 200
    assert d["rate_limit_headers"]["retry-after"] == "120"


def test_execute_request_post_success():
    mock_session = MagicMock()
    mock_resp = MagicMock(spec=requests.Response)
    mock_resp.status_code = 429
    mock_resp.content = b"Too Many Requests"
    mock_resp.url = "https://example.com/api"
    mock_resp.history = []
    mock_resp.headers = {"ratelimit-remaining": "0"}
    mock_session.post.return_value = mock_resp

    rec = execute_request(
        mock_session, "POST", "https://example.com/api", data={"user": "admin"}, attempt=2
    )

    assert rec.status == 429
    assert rec.method == "POST"
    assert rec.rate_limit_headers.get("ratelimit-remaining") == "0"


def test_execute_request_exception():
    mock_session = MagicMock()
    mock_session.get.side_effect = requests.RequestException("Connection refused")

    rec = execute_request(mock_session, "GET", "https://example.com/fail", attempt=1)

    assert rec.status == 0
    assert any("RequestException" in ind for ind in rec.lockout_indicators)


# ── Auth Flow Tests ──────────────────────────────────────────────────────────

@patch("rlcheck.engine.auth_flow.TerminalDashboard")
@patch("rlcheck.engine.auth_flow.TrackedSession")
def test_run_full_assessment_captcha_on_initial_page(mock_ts_cls, mock_dash_cls):
    mock_ts = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = "<html><div class='g-recaptcha'></div></html>"
    mock_resp.status_code = 200
    mock_ts.get.return_value = mock_resp
    mock_ts_cls.return_value = mock_ts

    safety = SafetyConfig()
    run_full_assessment(
        url="https://example.com",
        user=None,
        password=None,
        test_otp="000000",
        safety=safety,
        report_format="none",
        output_dir="reports",
        insecure=False,
        verbose=False,
    )

    # Dashboard should be stopped due to CAPTCHA
    mock_dash = mock_dash_cls.return_value
    assert mock_dash.stop.called


@patch("rlcheck.engine.auth_flow.TerminalDashboard")
@patch("rlcheck.engine.auth_flow.TrackedSession")
def test_run_login_assessment_no_form(mock_ts_cls, mock_dash_cls):
    mock_ts = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = "<html><body>No form here</body></html>"
    mock_resp.status_code = 200
    mock_ts.get.return_value = mock_resp
    mock_ts_cls.return_value = mock_ts

    safety = SafetyConfig()
    run_login_assessment(
        url="https://example.com",
        user=None,
        password=None,
        safety=safety,
        report_format="none",
        output_dir="reports",
        insecure=False,
        verbose=False,
    )

    mock_dash = mock_dash_cls.return_value
    assert mock_dash.stop.called


@patch("rlcheck.engine.auth_flow.TerminalDashboard")
@patch("rlcheck.engine.auth_flow.TrackedSession")
def test_run_otp_assessment_no_form(mock_ts_cls, mock_dash_cls):
    mock_ts = MagicMock()
    mock_resp = MagicMock()
    mock_resp.text = "<html><body>No OTP here</body></html>"
    mock_resp.status_code = 200
    mock_ts.get.return_value = mock_resp
    mock_ts_cls.return_value = mock_ts

    safety = SafetyConfig()
    run_otp_assessment(
        url="https://example.com",
        user=None,
        password=None,
        test_otp="000000",
        safety=safety,
        report_format="none",
        output_dir="reports",
        insecure=False,
        verbose=False,
    )

    mock_dash = mock_dash_cls.return_value
    assert mock_dash.stop.called


# ── Auth Flow Helpers Tests ──────────────────────────────────────────────────

def test_overall_confidence():
    from rlcheck.engine.auth_flow import _overall_confidence
    from rlcheck.detectors.rate_limit import RateLimitResult
    from rlcheck.detectors.lockout import LockoutResult

    assert _overall_confidence() == "LOW"
    r1 = RateLimitResult(confidence="MEDIUM")
    r2 = LockoutResult(confidence="HIGH")
    assert _overall_confidence(r1, r2) == "HIGH"


def test_save_reports(tmp_path):
    from rlcheck.engine.auth_flow import _save_reports
    from rlcheck.analysis.scoring import AssessmentScore
    from rlcheck.analysis.timeline import Timeline

    score = AssessmentScore()
    tl = Timeline()
    tl.add("Event 1")

    _save_reports(
        report_format="all",
        output_dir=str(tmp_path),
        target="https://example.com",
        flow={"login_detected": True},
        score=score,
        records=[],
        timeline=tl,
        config={"max_attempts": 5},
    )

    files = list(tmp_path.glob("rlcheck-*"))
    assert any(f.suffix == ".json" for f in files)
    assert any(f.suffix == ".html" for f in files)


@patch("time.sleep", return_value=None)
@patch("rlcheck.engine.auth_flow.execute_request")
def test_run_controlled_otp_test_rate_limit_stop(mock_exec, mock_sleep):
    from rlcheck.engine.auth_flow import _run_controlled_otp_test
    from rlcheck.discovery.otp import OTPFormInfo
    from rlcheck.reporters.terminal import TerminalDashboard
    from rlcheck.analysis.timeline import Timeline

    otp_form = OTPFormInfo(
        action="https://example.com/otp",
        method="POST",
        otp_field="otp",
    )
    r1 = RequestRecord(attempt=1, status=200)
    r2 = RequestRecord(attempt=2, status=429)
    mock_exec.side_effect = [r1, r2]

    ts = TrackedSession()
    ts.session.get = MagicMock(return_value=MagicMock(text="<html></html>"))
    dash = TerminalDashboard(target="https://example.com")
    tl = Timeline()
    safety = SafetyConfig(max_attempts=5, min_interval=1.0)

    records, bodies, stop_reason = _run_controlled_otp_test(
        ts=ts,
        otp_form=otp_form,
        test_otp="000000",
        safety=safety,
        dashboard=dash,
        timeline=tl,
    )

    assert stop_reason == "rate_limit_detected"
    assert len(records) == 2


@patch("time.sleep", return_value=None)
@patch("rlcheck.engine.auth_flow.execute_request")
def test_run_login_rate_test_stop_lockout(mock_exec, mock_sleep):
    from rlcheck.engine.auth_flow import _run_login_rate_test
    from rlcheck.discovery.login import LoginFormInfo
    from rlcheck.reporters.terminal import TerminalDashboard
    from rlcheck.analysis.timeline import Timeline

    login_form = LoginFormInfo(
        action="https://example.com/login",
        method="POST",
        username_field="user",
        password_field="pass",
    )
    r1 = RequestRecord(attempt=1, status=423)
    mock_exec.side_effect = [r1]

    ts = TrackedSession()
    ts.get = MagicMock(return_value=MagicMock(text="<html></html>"))
    dash = TerminalDashboard(target="https://example.com")
    tl = Timeline()
    safety = SafetyConfig(max_attempts=5, min_interval=1.0)

    records, bodies, stop_reason = _run_login_rate_test(
        ts=ts,
        login_form=login_form,
        user="test@example.com",
        password="bad_password",
        safety=safety,
        dashboard=dash,
        timeline=tl,
    )

    assert stop_reason == "lockout_detected"
    assert len(records) == 1
