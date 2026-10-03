"""OTP form discovery — detect OTP / verification-code input fields."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urljoin

from bs4 import BeautifulSoup, Tag

from rlcheck.discovery.csrf import extract_csrf_token

# Common OTP field names / IDs / placeholders
_OTP_NAME_HINTS = re.compile(
    r"(otp|one.?time|verification.?code|verify.?code|auth.?code|"
    r"mfa.?code|totp|sms.?code|pin.?code|security.?code|token)",
    re.IGNORECASE,
)

# Page-level keywords indicating an OTP / verification page
_OTP_PAGE_HINTS = re.compile(
    r"(enter.*(otp|code|verification)|verification\s+code|"
    r"one.time\s+password|two.factor|2fa|multi.factor|"
    r"we.sent.*code|check\s+your\s+(email|phone|sms))",
    re.IGNORECASE,
)


@dataclass
class OTPFormInfo:
    """Structured representation of a discovered OTP / verification form."""
    action: str = ""
    method: str = "POST"
    otp_field: Optional[str] = None
    csrf_field: Optional[str] = None
    csrf_value: Optional[str] = None
    hidden_fields: dict = field(default_factory=dict)
    confidence: str = "LOW"
    raw_html: str = ""


def detect_otp_page(html: str, base_url: str) -> Optional[OTPFormInfo]:
    """Return an ``OTPFormInfo`` if the page appears to be an OTP challenge.

    Combines form-field heuristics with page-level text analysis to assign a
    confidence score.
    """
    soup = BeautifulSoup(html, "html.parser")

    # Page-level signal
    page_text = soup.get_text(separator=" ")
    page_signal = bool(_OTP_PAGE_HINTS.search(page_text))

    forms = soup.find_all("form")
    best: Optional[OTPFormInfo] = None
    best_score = 0

    for form in forms:
        info, score = _parse_otp_form(form, base_url)
        if page_signal:
            score += 2
        if score > best_score:
            best_score = score
            best = info

    # If no form found but there is page-level signal, create a stub
    if best is None and page_signal:
        best = OTPFormInfo(action=base_url, confidence="LOW")
        best_score = 2

    if best is not None:
        if best_score >= 5:
            best.confidence = "HIGH"
        elif best_score >= 3:
            best.confidence = "MEDIUM"
        else:
            best.confidence = "LOW"

    return best


def _parse_otp_form(form_tag: Tag, base_url: str):
    """Parse a single form and return ``(OTPFormInfo, score)``."""
    info = OTPFormInfo()
    info.raw_html = str(form_tag)
    info.method = (form_tag.get("method") or "POST").upper()
    action_raw = form_tag.get("action") or ""
    info.action = urljoin(base_url, action_raw) if action_raw else base_url

    score = 0
    inputs = form_tag.find_all("input")

    for inp in inputs:
        itype = (inp.get("type") or "text").lower()
        name = inp.get("name") or ""
        iid = inp.get("id") or ""
        placeholder = inp.get("placeholder") or ""
        autocomplete = inp.get("autocomplete") or ""
        label_text = _find_label_text(form_tag, iid)

        combined = f"{name} {iid} {placeholder} {autocomplete} {label_text}"

        if itype == "hidden":
            info.hidden_fields[name] = inp.get("value", "")
            continue

        if _OTP_NAME_HINTS.search(combined):
            info.otp_field = name or iid
            score += 3
            continue

        # Numeric-only short field (4–8 chars) is suspicious but not conclusive
        maxlen = inp.get("maxlength")
        if maxlen and maxlen.isdigit() and 4 <= int(maxlen) <= 8:
            if itype in ("text", "number", "tel"):
                score += 1
                if info.otp_field is None:
                    info.otp_field = name or iid

        if autocomplete == "one-time-code":
            score += 3
            if info.otp_field is None:
                info.otp_field = name or iid

    csrf = extract_csrf_token(form_tag)
    if csrf:
        info.csrf_field, info.csrf_value = csrf
        score += 1

    return info, score


def _find_label_text(form_tag: Tag, field_id: str) -> str:
    """Find the text of a ``<label>`` associated with *field_id*."""
    if not field_id:
        return ""
    label = form_tag.find("label", attrs={"for": field_id})
    if label:
        return label.get_text(separator=" ", strip=True)
    return ""
