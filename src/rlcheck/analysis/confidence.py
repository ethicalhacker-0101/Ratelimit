"""Confidence module — utility helpers for confidence scoring."""
from __future__ import annotations

from typing import List


def merge_confidences(levels: List[str]) -> str:
    """Return the highest confidence among *levels*.

    Order: HIGH > MEDIUM > LOW.
    """
    rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    best = max(levels, key=lambda l: rank.get(l, 0), default="LOW")
    return best


def confidence_from_signals(signals: int) -> str:
    """Map a raw signal count to a confidence label."""
    if signals >= 4:
        return "HIGH"
    elif signals >= 2:
        return "MEDIUM"
    return "LOW"
