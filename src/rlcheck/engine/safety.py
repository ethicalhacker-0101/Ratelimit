"""Safety configuration and validation.

Enforces hard limits on request volume, interval, and timeout to guarantee
that RLCheck Pro stays in controlled, low-volume testing mode.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

# ── Hard limits (cannot be overridden) ──────────────────────────────────────

MAX_ATTEMPTS_HARD_LIMIT = 50
MIN_INTERVAL_HARD_LIMIT = 1.0        # seconds
MAX_TIMEOUT = 60                      # seconds
DEFAULT_ATTEMPTS = 10
DEFAULT_INTERVAL = 2.0
DEFAULT_TIMEOUT = 15


@dataclass
class SafetyConfig:
    """User-adjustable safety knobs, validated against hard limits."""
    max_attempts: int = DEFAULT_ATTEMPTS
    min_interval: float = DEFAULT_INTERVAL
    timeout: int = DEFAULT_TIMEOUT

    def __post_init__(self):
        # Clamp silently — validate_safety() provides user-facing errors
        self.max_attempts = min(self.max_attempts, MAX_ATTEMPTS_HARD_LIMIT)
        self.min_interval = max(self.min_interval, MIN_INTERVAL_HARD_LIMIT)
        self.timeout = min(self.timeout, MAX_TIMEOUT)


def validate_safety(config: SafetyConfig) -> Tuple[bool, str]:
    """Return ``(True, "")`` if config is acceptable, else ``(False, reason)``."""
    if config.max_attempts < 1:
        return False, "Attempts must be at least 1."
    if config.max_attempts > MAX_ATTEMPTS_HARD_LIMIT:
        return False, f"Attempts exceed hard limit of {MAX_ATTEMPTS_HARD_LIMIT}."
    if config.min_interval < MIN_INTERVAL_HARD_LIMIT:
        return False, f"Interval must be >= {MIN_INTERVAL_HARD_LIMIT}s."
    if config.timeout < 1:
        return False, "Timeout must be at least 1 second."
    if config.timeout > MAX_TIMEOUT:
        return False, f"Timeout exceeds hard limit of {MAX_TIMEOUT}s."
    return True, ""
