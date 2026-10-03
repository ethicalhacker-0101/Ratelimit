"""Login form discovery — parse HTML to find username/password fields and form metadata."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from rlcheck.discovery.csrf import extract_csrf_token

# Heuristics for field identification
_USERNAME_HINTS = re.compile(
    r"(user|email|login|account|identifier|phone|mobile)", re.IGNORECASE
)
_PASSWORD_HINTS = re.compile(r"(pass|secret|pwd|credential)", re.IGNORECASE)


@dataclass
class LoginFormInfo:
    """Structured representation of a discovered login form."""
    action: str = ""
    method: str = "POST"
    username_field: Optional[str] = None
    password_field: Optional[str] = None
    csrf_field: Optional[str] = None
    csrf_value: Optional[str] = None
    hidden_fields: dict = field(default_factory=dict)
    submit_value: Optional[str] = None
    raw_html: str = ""
    confidence: str = "LOW"  # LOW / MEDIUM / HIGH


def discover_login_form(html: str, base_url: str) -> Optional[LoginFormInfo]:
    """Inspect *html* and return a ``LoginFormInfo`` if a login form is found.

    Parameters
    ----------
    html : str
        Raw HTML of the page fetched via GET.
    base_url : str
        The URL the HTML was retrieved from — used to resolve relative ``action`` URLs.

    Returns
    -------
    LoginFormInfo or None
    """
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")

    best: Optional[LoginFormInfo] = None
    best_score = 0

    for form in forms:
        info = _parse_form(form, base_url)
        score = _score_login_form(info, form)
        if score > best_score:
            best_score = score
            best = info

    if best is not None:
        if best_score >= 4:
            best.confidence = "HIGH"
        elif best_score >= 2:
            best.confidence = "MEDIUM"
        else:
            best.confidence = "LOW"

    return best


def _parse_form(form_tag, base_url: str) -> LoginFormInfo:
    """Extract fields and metadata from a single ``<form>`` tag."""
    info = LoginFormInfo()
    info.raw_html = str(form_tag)
    info.method = (form_tag.get("method") or "POST").upper()
    action_raw = form_tag.get("action") or ""
    info.action = urljoin(base_url, action_raw) if action_raw else base_url

    inputs = form_tag.find_all("input")
    for inp in inputs:
        itype = (inp.get("type") or "text").lower()
        name = inp.get("name") or ""
        iid = inp.get("id") or ""
        placeholder = inp.get("placeholder") or ""
        autocomplete = inp.get("autocomplete") or ""

        combined = f"{name} {iid} {placeholder} {autocomplete}"

        if itype == "hidden":
            info.hidden_fields[name] = inp.get("value", "")
            # Check if this hidden field is a CSRF token
            csrf = extract_csrf_token(form_tag)
            if csrf:
                info.csrf_field, info.csrf_value = csrf
            continue

        if itype == "submit":
            info.submit_value = inp.get("value", "")
            continue

        if itype == "password" or _PASSWORD_HINTS.search(combined):
            info.password_field = name or iid
            continue

        if itype in ("text", "email", "tel") or _USERNAME_HINTS.search(combined):
            if info.username_field is None:
                info.username_field = name or iid

    # Also look for <button type="submit">
    if not info.submit_value:
        btn = form_tag.find("button", attrs={"type": "submit"})
        if btn:
            info.submit_value = btn.get_text(strip=True)

    # Fall-back CSRF extraction at form level
    if info.csrf_field is None:
        csrf = extract_csrf_token(form_tag)
        if csrf:
            info.csrf_field, info.csrf_value = csrf

    return info


def _score_login_form(info: LoginFormInfo, form_tag) -> int:
    """Heuristic score — higher means more likely to be a real login form."""
    score = 0
    if info.password_field:
        score += 3
    if info.username_field:
        score += 2
    if info.csrf_field:
        score += 1
    # Check form text for login-related words
    text = form_tag.get_text(separator=" ").lower()
    for kw in ("log in", "login", "sign in", "signin", "authenticate"):
        if kw in text:
            score += 1
            break
    return score
