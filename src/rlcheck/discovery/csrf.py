"""CSRF token extraction from HTML forms."""
from __future__ import annotations

import re
from typing import Optional, Tuple

from bs4 import Tag

# Common CSRF field names
_CSRF_NAMES = re.compile(
    r"(csrf|xsrf|_token|authenticity_token|request_verification_token|"
    r"__requestverificationtoken|csrfmiddlewaretoken|_csrf_token|"
    r"antiforgery|anti.forgery)",
    re.IGNORECASE,
)


def extract_csrf_token(form_tag: Tag) -> Optional[Tuple[str, str]]:
    """Return ``(field_name, value)`` of the CSRF token if found, else ``None``.

    Searches hidden ``<input>`` and ``<meta>`` tags within the form (and its
    parent document) for common CSRF field-name patterns.
    """
    # 1. Check hidden inputs inside the form
    for inp in form_tag.find_all("input", attrs={"type": "hidden"}):
        name = inp.get("name") or ""
        if _CSRF_NAMES.search(name):
            return (name, inp.get("value", ""))

    # 2. Check <meta> tags in the document (Django / Rails style)
    root = form_tag.find_parent("html") or form_tag
    for meta in root.find_all("meta"):
        meta_name = meta.get("name") or meta.get("property") or ""
        if _CSRF_NAMES.search(meta_name):
            content = meta.get("content", "")
            if content:
                return (meta_name, content)

    return None


def refresh_csrf_token(html: str) -> Optional[Tuple[str, str]]:
    """Re-extract CSRF token from a full HTML page string.

    Useful when a new page has been loaded (e.g., after redirect to OTP page)
    and the token may have rotated.
    """
    from bs4 import BeautifulSoup
    soup = BeautifulSoup(html, "html.parser")
    forms = soup.find_all("form")
    for form in forms:
        token = extract_csrf_token(form)
        if token:
            return token
    return None
