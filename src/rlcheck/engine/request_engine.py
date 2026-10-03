"""Low-level HTTP request engine with response fingerprinting and evidence capture.

Every request is recorded as a ``RequestRecord`` that feeds into the
detectors and reporters.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

import requests

from rlcheck.detectors.fingerprint import ResponseFingerprint, build_fingerprint


@dataclass
class RequestRecord:
    """Evidence record for a single controlled request."""
    timestamp: str = ""
    attempt: int = 0
    method: str = ""
    url: str = ""
    status: int = 0
    elapsed: float = 0.0
    response_size: int = 0
    fingerprint: Optional[ResponseFingerprint] = None
    redirect_count: int = 0
    final_url: str = ""
    rate_limit_headers: Dict[str, str] = field(default_factory=dict)
    challenge_detected: bool = False
    lockout_indicators: List[str] = field(default_factory=list)
    selected_headers: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Serialisable dict — excludes raw response data."""
        return {
            "timestamp": self.timestamp,
            "attempt": self.attempt,
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "elapsed_s": round(self.elapsed, 4),
            "response_size": self.response_size,
            "fingerprint": self.fingerprint.to_dict() if self.fingerprint else None,
            "redirect_count": self.redirect_count,
            "final_url": self.final_url,
            "rate_limit_headers": self.rate_limit_headers,
            "challenge_detected": self.challenge_detected,
            "lockout_indicators": self.lockout_indicators,
            "selected_headers": self.selected_headers,
        }


# Rate-limit header names we look for
_RL_HEADERS = {
    "retry-after", "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
    "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
}

# Security headers of interest
_SEC_HEADERS = {
    "strict-transport-security", "content-security-policy",
    "x-content-type-options", "x-frame-options", "x-xss-protection",
    "referrer-policy", "permissions-policy",
}


def execute_request(
    session: requests.Session,
    method: str,
    url: str,
    data: Optional[dict] = None,
    attempt: int = 0,
    timeout: int = 15,
) -> RequestRecord:
    """Send a single request and capture evidence.

    Parameters
    ----------
    session : requests.Session
        The tracked session to use.
    method : str
        HTTP method (``GET`` or ``POST``).
    url : str
        Target URL.
    data : dict or None
        POST body.
    attempt : int
        Sequential attempt number for logging.
    timeout : int
        Request timeout in seconds.

    Returns
    -------
    RequestRecord
    """
    record = RequestRecord(
        timestamp=datetime.now(timezone.utc).isoformat(),
        attempt=attempt,
        method=method.upper(),
        url=url,
    )

    t0 = time.monotonic()
    try:
        if method.upper() == "GET":
            resp = session.get(url, timeout=timeout, allow_redirects=True)
        else:
            resp = session.post(url, data=data, timeout=timeout, allow_redirects=True)
    except requests.RequestException as exc:
        record.elapsed = time.monotonic() - t0
        record.status = 0
        record.lockout_indicators.append(f"RequestException: {exc}")
        return record

    record.elapsed = time.monotonic() - t0
    record.status = resp.status_code
    record.response_size = len(resp.content)
    record.redirect_count = len(resp.history)
    record.final_url = resp.url

    # Rate-limit headers
    for hdr in _RL_HEADERS:
        val = resp.headers.get(hdr)
        if val:
            record.rate_limit_headers[hdr] = val

    # Selected security headers
    for hdr in _SEC_HEADERS:
        val = resp.headers.get(hdr)
        if val:
            record.selected_headers[hdr] = val

    # Build fingerprint
    record.fingerprint = build_fingerprint(resp)

    return record
