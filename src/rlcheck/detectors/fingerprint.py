"""Response fingerprinting — status + normalised headers + body hash + length.

Used to detect behavioural changes across sequential requests without storing
full response bodies.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Optional

import requests


@dataclass
class ResponseFingerprint:
    """Compact fingerprint of an HTTP response."""
    status: int = 0
    body_hash: str = ""           # SHA-256 of response body
    body_length: int = 0
    content_type: str = ""
    combined_hash: str = ""       # SHA-256 of (status + headers + body_hash + length)

    def to_dict(self) -> dict:
        return {
            "status": self.status,
            "body_hash": self.body_hash,
            "body_length": self.body_length,
            "content_type": self.content_type,
            "combined": self.combined_hash,
        }

    def __eq__(self, other):
        if not isinstance(other, ResponseFingerprint):
            return NotImplemented
        return self.combined_hash == other.combined_hash

    def __hash__(self):
        return hash(self.combined_hash)


def build_fingerprint(resp: requests.Response) -> ResponseFingerprint:
    """Create a ``ResponseFingerprint`` from a ``requests.Response``."""
    body = resp.content
    body_hash = hashlib.sha256(body).hexdigest()[:16]
    content_type = resp.headers.get("content-type", "")

    # Build the combined hash from deterministic components
    components = f"{resp.status_code}|{content_type}|{body_hash}|{len(body)}"
    combined = hashlib.sha256(components.encode()).hexdigest()[:16]

    return ResponseFingerprint(
        status=resp.status_code,
        body_hash=body_hash,
        body_length=len(body),
        content_type=content_type,
        combined_hash=combined,
    )


def fingerprints_changed(fps: list[ResponseFingerprint]) -> bool:
    """Return ``True`` if the list of fingerprints contains more than one
    distinct combined hash — indicating a behavioural change."""
    if len(fps) < 2:
        return False
    first = fps[0].combined_hash
    return any(fp.combined_hash != first for fp in fps)


def detect_fingerprint_shift(fps: list[ResponseFingerprint]) -> Optional[int]:
    """Return the 0-based index where the fingerprint first changed, or ``None``."""
    if len(fps) < 2:
        return None
    first = fps[0].combined_hash
    for idx, fp in enumerate(fps[1:], start=1):
        if fp.combined_hash != first:
            return idx
    return None
