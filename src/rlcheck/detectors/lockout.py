"""Lockout detection — determine if repeated failures trigger account/session locking.

Analyses response patterns for lockout-related keywords, status transitions,
and timing changes that suggest temporary account or session locking.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import List, Optional

from rlcheck.engine.request_engine import RequestRecord

_LOCKOUT_PATTERNS = re.compile(
    r"(account\s*(temporarily\s+)?(locked|disabled|suspended|blocked)|"
    r"too\s+many\s+(failed\s+)?(attempts|tries)|"
    r"temporarily\s+(locked|blocked|suspended)|"
    r"try\s+again\s+(in|after)\s+\d|"
    r"verification\s+temporarily\s+blocked|"
    r"login\s+(temporarily\s+)?(disabled|blocked)|"
    r"session\s+(expired|invalidated|locked))",
    re.IGNORECASE,
)


@dataclass
class LockoutResult:
    """Outcome of lockout detection."""
    detected: bool = False
    possible: bool = False        # Weaker signal — behaviour is suspicious
    confidence: str = "LOW"
    attempts_before_lockout: Optional[int] = None
    duration_hint: Optional[str] = None
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "detected": self.detected,
            "possible": self.possible,
            "confidence": self.confidence,
            "attempts_before_lockout": self.attempts_before_lockout,
            "duration_hint": self.duration_hint,
            "evidence": self.evidence,
        }


def detect_lockout(records: List[RequestRecord]) -> LockoutResult:
    """Analyse ``RequestRecord`` sequence for lockout signals."""
    result = LockoutResult()
    signals = 0

    for rec in records:
        # Status 423 (Locked) is a strong signal
        if rec.status == 423:
            result.evidence.append(f"Attempt {rec.attempt}: HTTP 423 Locked")
            if result.attempts_before_lockout is None:
                result.attempts_before_lockout = rec.attempt
            signals += 3

        # Check lockout indicators from the request engine
        for indicator in rec.lockout_indicators:
            result.evidence.append(f"Attempt {rec.attempt}: {indicator}")
            signals += 1

        # Retry-After header implies temporary lockout
        retry_after = rec.rate_limit_headers.get("retry-after")
        if retry_after:
            result.duration_hint = f"{retry_after} seconds"
            result.evidence.append(
                f"Attempt {rec.attempt}: Retry-After={retry_after}"
            )
            if result.attempts_before_lockout is None:
                result.attempts_before_lockout = rec.attempt
            signals += 2

    # Detect behavioural shift: sustained status change in the tail
    if len(records) >= 3:
        statuses = [r.status for r in records]
        initial = statuses[0]
        # Check if later responses differ consistently
        tail = statuses[len(statuses) // 2:]
        if all(s != initial for s in tail) and all(s == tail[0] for s in tail):
            result.evidence.append(
                f"Status shifted from {initial} to {tail[0]} at midpoint"
            )
            signals += 1

    # Classify
    if signals >= 4:
        result.detected = True
        result.confidence = "HIGH"
    elif signals >= 2:
        result.detected = True
        result.possible = True
        result.confidence = "MEDIUM"
    elif signals >= 1:
        result.possible = True
        result.confidence = "LOW"

    return result


def should_stop_for_lockout(record: RequestRecord) -> bool:
    """Return ``True`` if this response suggests an immediate lockout."""
    if record.status == 423:
        return True
    return False
