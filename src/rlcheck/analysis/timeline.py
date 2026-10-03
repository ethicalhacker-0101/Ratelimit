"""Timeline — chronological event log for the assessment."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List


@dataclass
class TimelineEvent:
    """A single timestamped event."""
    timestamp: str = ""
    event: str = ""

    def to_dict(self) -> dict:
        return {"timestamp": self.timestamp, "event": self.event}


class Timeline:
    """Ordered list of events for the assessment report."""

    def __init__(self):
        self.events: List[TimelineEvent] = []

    def add(self, event: str, timestamp: str | None = None):
        """Append an event with the current UTC time."""
        ts = timestamp or datetime.now(timezone.utc).strftime("%H:%M:%S")
        self.events.append(TimelineEvent(timestamp=ts, event=event))

    def to_list(self) -> List[dict]:
        return [e.to_dict() for e in self.events]

    def __len__(self):
        return len(self.events)
