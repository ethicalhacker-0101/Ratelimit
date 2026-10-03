"""JSON report generation and loading.

Generates a structured JSON report at ``reports/rlcheck-YYYYMMDD-HHMMSS.json``.
Sensitive values (passwords, tokens, cookies) are never stored in the report.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from rlcheck import __tool_name__, __version__
from rlcheck.analysis.scoring import AssessmentScore
from rlcheck.analysis.timeline import Timeline
from rlcheck.engine.request_engine import RequestRecord


def generate_json_report(
    *,
    target: str,
    flow: dict,
    score: AssessmentScore,
    records: List[RequestRecord],
    timeline: Timeline,
    config: dict,
    output_dir: str = "reports",
) -> str:
    """Write a JSON report and return the file path."""
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"rlcheck-{ts}.json"
    filepath = os.path.join(output_dir, filename)

    report: Dict[str, Any] = {
        "tool": __tool_name__,
        "version": __version__,
        "generated_utc": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "flow": flow,
        "assessment": score.to_dict(),
        "evidence": [r.to_dict() for r in records],
        "timeline": timeline.to_list(),
        "test_configuration": config,
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, default=str)

    return filepath


def load_report(path: str) -> dict:
    """Load a previously saved JSON report."""
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)
