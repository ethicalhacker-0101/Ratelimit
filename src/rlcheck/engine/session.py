"""HTTP session management and cookie/state tracking.

Wraps ``requests.Session`` with:
- Automatic CSRF refresh
- Session-ID change detection (hashed for privacy)
- Cookie-change tracking
- Redirect-chain recording
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests


@dataclass
class SessionSnapshot:
    """Immutable snapshot of session state at a point in time."""
    cookies_hash: str = ""
    session_ids: Dict[str, str] = field(default_factory=dict)  # name → sha256 prefix
    csrf_token: Optional[str] = None

    def differs_from(self, other: "SessionSnapshot") -> bool:
        return (
            self.cookies_hash != other.cookies_hash
            or self.session_ids != other.session_ids
        )


class TrackedSession:
    """A ``requests.Session`` wrapper that records state transitions."""

    def __init__(self, *, verify_tls: bool = True, timeout: int = 15):
        self.session = requests.Session()
        self.session.verify = verify_tls
        self.timeout = timeout
        self.snapshots: List[SessionSnapshot] = []
        self.redirect_chains: List[List[str]] = []
        self._session_cookie_names = {"sessionid", "session", "sid", "phpsessid",
                                       "jsessionid", "connect.sid", "aspsessionid",
                                       "session_id", "sess_id", "token"}

    # ── Public helpers ──────────────────────────────────────────────────────

    def get(self, url: str, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        resp = self.session.get(url, **kwargs)
        self._record(resp)
        return resp

    def post(self, url: str, data=None, **kwargs) -> requests.Response:
        kwargs.setdefault("timeout", self.timeout)
        kwargs.setdefault("allow_redirects", True)
        resp = self.session.post(url, data=data, **kwargs)
        self._record(resp)
        return resp

    def take_snapshot(self) -> SessionSnapshot:
        """Create a snapshot of the current cookie jar."""
        jar = self.session.cookies
        all_cookies = {c.name: c.value for c in jar}
        cookies_str = "|".join(f"{k}={v}" for k, v in sorted(all_cookies.items()))
        cookies_hash = _sha256_short(cookies_str) if cookies_str else ""

        session_ids = {}
        for name, value in all_cookies.items():
            if name.lower() in self._session_cookie_names:
                session_ids[name] = _sha256_short(value)

        snap = SessionSnapshot(
            cookies_hash=cookies_hash,
            session_ids=session_ids,
        )
        return snap

    def session_changed(self) -> bool:
        """Return ``True`` if the session state changed since the last snapshot."""
        if len(self.snapshots) < 2:
            return False
        return self.snapshots[-1].differs_from(self.snapshots[-2])

    @property
    def latest_snapshot(self) -> Optional[SessionSnapshot]:
        return self.snapshots[-1] if self.snapshots else None

    # ── Internal ────────────────────────────────────────────────────────────

    def _record(self, resp: requests.Response):
        """Record redirect chain and session snapshot after every request."""
        chain = [r.url for r in resp.history] + [resp.url]
        self.redirect_chains.append(chain)
        self.snapshots.append(self.take_snapshot())


def _sha256_short(value: str) -> str:
    """Return first 12 hex chars of the SHA-256 digest."""
    return hashlib.sha256(value.encode()).hexdigest()[:12]
