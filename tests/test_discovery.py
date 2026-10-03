import pytest
from bs4 import BeautifulSoup

from rlcheck.discovery.csrf import extract_csrf_token, refresh_csrf_token
from rlcheck.discovery.login import discover_login_form
from rlcheck.discovery.otp import detect_otp_page


# ── CSRF Extraction Tests ────────────────────────────────────────────────────

def test_extract_csrf_from_hidden_input():
    html = """
    <form action="/login" method="POST">
        <input type="hidden" name="csrfmiddlewaretoken" value="secret_csrf_123">
        <input type="text" name="username">
    </form>
    """
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form")
    result = extract_csrf_token(form)
    assert result is not None
    name, val = result
    assert name == "csrfmiddlewaretoken"
    assert val == "secret_csrf_123"


def test_extract_csrf_from_meta_tag():
    html = """
    <html>
    <head>
        <meta name="csrf-token" content="meta_csrf_999">
    </head>
    <body>
        <form action="/login" method="POST">
            <input type="text" name="username">
        </form>
    </body>
    </html>
    """
    soup = BeautifulSoup(html, "html.parser")
    form = soup.find("form")
    result = extract_csrf_token(form)
    assert result is not None
    name, val = result
    assert name == "csrf-token"
    assert val == "meta_csrf_999"


def test_refresh_csrf_token():
    html = """
    <html><body>
        <form action="/otp" method="POST">
            <input type="hidden" name="_csrf_token" value="refreshed_token_456">
            <input type="text" name="otp">
        </form>
    </body></html>
    """
    token = refresh_csrf_token(html)
    assert token is not None
    assert token[0] == "_csrf_token"
    assert token[1] == "refreshed_token_456"


# ── Login Form Discovery Tests ───────────────────────────────────────────────

def test_discover_login_form_success():
    html = """
    <html><body>
        <form action="/auth/login" method="POST">
            <input type="text" name="email" placeholder="Enter your email">
            <input type="password" name="password" placeholder="Password">
            <input type="hidden" name="_token" value="abc123csrf">
            <button type="submit">Sign In</button>
        </form>
    </body></html>
    """
    info = discover_login_form(html, "https://example.com")
    assert info is not None
    assert info.action == "https://example.com/auth/login"
    assert info.username_field == "email"
    assert info.password_field == "password"
    assert info.csrf_field == "_token"
    assert info.csrf_value == "abc123csrf"
    assert info.submit_value == "Sign In"
    assert info.confidence in ("MEDIUM", "HIGH")


def test_discover_login_form_none_found():
    html = "<html><body><p>Just plain text here</p></body></html>"
    info = discover_login_form(html, "https://example.com")
    assert info is None


# ── OTP Page Discovery Tests ─────────────────────────────────────────────────

def test_detect_otp_page_form():
    html = """
    <html><body>
        <h2>Two-Factor Authentication</h2>
        <p>Please enter the verification code sent to your phone.</p>
        <form action="/verify-otp" method="POST">
            <label for="otp_input">OTP Code</label>
            <input type="text" id="otp_input" name="otp" autocomplete="one-time-code" maxlength="6">
            <input type="submit" value="Verify">
        </form>
    </body></html>
    """
    info = detect_otp_page(html, "https://example.com")
    assert info is not None
    assert info.action == "https://example.com/verify-otp"
    assert info.otp_field == "otp"
    assert info.confidence == "HIGH"


def test_detect_otp_page_no_otp():
    html = "<html><body><h1>Dashboard</h1><p>Welcome to your account.</p></body></html>"
    info = detect_otp_page(html, "https://example.com")
    assert info is None
