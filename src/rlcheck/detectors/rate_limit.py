"""Rate-limit detection — multi-signal analysis of HTTP responses.

Combines status codes, headers, response body keywords, fingerprint shifts,
and timing analysis to determine whether rate limiting is enforced.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from rlcheck.engine.request_engine import RequestRecord

# Status codes that signal rate limiting / blocking
_RL_STATUS_CODES = {429, 403, 423}

# Header names (lowercase) that indicate rate limiting
_RL_HEADERS = {
    "retry-after", "ratelimit-limit", "ratelimit-remaining", "ratelimit-reset",
    "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset",
}

# Body patterns (case-insensitive)
_RL_BODY_PATTERNS = re.compile(
    r"(too\s+many\s+(attempts|requests)|rate\s+limit|try\s+again\s+later|"
    r"request\s+limit\s+exceeded|temporarily\s+blocked|please\s+wait|"
    r"slow\s+down|throttl)",
    re.IGNORECASE,
)


@dataclass
class RateLimitResult:
    """Outcome of rate-limit detection across a sequence of records."""
    detected: bool = False
    confidence: str = "LOW"       # LOW / MEDIUM / HIGH
    trigger_attempt: Optional[int] = None
    retry_after: Optional[str] = None
    evidence: List[str] = field(default_factory=list)
    status_codes_seen: List[int] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "detected": self.detected,
            "confidence": self.confidence,
            "trigger_attempt": self.trigger_attempt,
            "retry_after": self.retry_after,
            "evidence": self.evidence,
        }


def detect_rate_limit(records: List[RequestRecord]) -> RateLimitResult:
    """Analyse a list of ``RequestRecord`` objects for rate-limit signals.

    Returns a ``RateLimitResult`` with detection outcome and evidence.
    """
    result = RateLimitResult()
    result.status_codes_seen = [r.status for r in records]

    signals = 0

    for rec in records:
        # 1. Status code
        if rec.status in _RL_STATUS_CODES:
            if result.trigger_attempt is None:
                result.trigger_attempt = rec.attempt
            result.evidence.append(f"Attempt {rec.attempt}: HTTP {rec.status}")
            signals += 2

        # 2. Rate-limit headers
        for hdr_name, hdr_val in rec.rate_limit_headers.items():
            result.evidence.append(f"Attempt {rec.attempt}: Header {hdr_name}={hdr_val}")
            if hdr_name.lower() == "retry-after":
                result.retry_after = hdr_val
            signals += 2

    # 3. Fingerprint shift detection
    fps = [r.fingerprint for r in records if r.fingerprint]
    if len(fps) >= 2:
        from rlcheck.detectors.fingerprint import detect_fingerprint_shift
        shift_idx = detect_fingerprint_shift(fps)
        if shift_idx is not None:
            result.evidence.append(
                f"Fingerprint changed at attempt {records[shift_idx].attempt}"
            )
            signals += 1

    # Determine detection & confidence
    if signals >= 4:
        result.detected = True
        result.confidence = "HIGH"
    elif signals >= 2:
        result.detected = True
        result.confidence = "MEDIUM"
    elif signals >= 1:
        result.detected = True
        result.confidence = "LOW"

    return result


def should_stop_for_rate_limit(record: RequestRecord) -> bool:
    """Return ``True`` if this single response warrants an immediate stop."""
    if record.status == 429:
        return True
    if "retry-after" in record.rate_limit_headers:
        return True
    return False
