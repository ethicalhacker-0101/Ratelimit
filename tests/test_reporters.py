import os
import json
import pytest

from rlcheck.reporters.json import generate_json_report, load_report
from rlcheck.reporters.html import render_html_report
from rlcheck.reporters.terminal import TerminalDashboard
from rlcheck.analysis.scoring import AssessmentScore, Finding
from rlcheck.analysis.timeline import Timeline
from rlcheck.engine.request_engine import RequestRecord


def test_generate_and_load_json_report(tmp_path):
    score = AssessmentScore(
        findings=[
            Finding(
                category="OTP RATE LIMITING",
                status="DETECTED",
                confidence="HIGH",
                risk_summary="Rate limiting active",
            )
        ]
    )
    records = [
        RequestRecord(attempt=1, status=200, method="POST", url="https://example.com/otp")
    ]
    timeline = Timeline()
    timeline.add("Started test")

    path = generate_json_report(
        target="https://example.com",
        flow={"type": "full"},
        score=score,
        records=records,
        timeline=timeline,
        config={"attempts": 5},
        output_dir=str(tmp_path),
    )

    assert os.path.exists(path)
    loaded = load_report(path)
    assert loaded["target"] == "https://example.com"
    assert loaded["flow"]["type"] == "full"
    assert len(loaded["assessment"]["findings"]) == 1
    assert loaded["assessment"]["findings"][0]["category"] == "OTP RATE LIMITING"


def test_render_html_report():
    data = {
        "tool": "RLCheck Pro",
        "version": "1.0.0",
        "generated_utc": "2026-10-04T00:00:00Z",
        "target": "https://example.com",
        "flow": {"type": "auth"},
        "assessment": {
            "overall_confidence": "HIGH",
            "findings": [
                {
                    "category": "OTP RATE LIMITING",
                    "status": "DETECTED",
                    "confidence": "HIGH",
                    "risk_summary": "Rate limiting is active.",
                    "recommendation": "Review threshold.",
                    "evidence": ["HTTP 429 received"],
                }
            ],
        },
        "evidence": [
            {
                "attempt": 1,
                "timestamp": "2026-10-04T00:00:01Z",
                "method": "POST",
                "url": "https://example.com/otp",
                "status": 429,
                "elapsed_s": 0.12,
                "response_size": 250,
                "rate_limit_headers": {"retry-after": "60"},
            }
        ],
        "timeline": [{"timestamp": "00:00:00", "event": "Scan started"}],
        "test_configuration": {"max_attempts": 5},
    }

    html = render_html_report(data)
    assert "RLCheck Pro" in html
    assert "https://example.com" in html
    assert "OTP RATE LIMITING" in html
    assert "429" in html


def test_terminal_dashboard_build():
    dashboard = TerminalDashboard(
        target="https://example.com",
        flow="LOGIN -> OTP",
        login_endpoint="https://example.com/login",
        otp_endpoint="https://example.com/otp",
    )
    dashboard.records.append(
        RequestRecord(attempt=1, status=200, method="POST", url="https://example.com/login")
    )
    layout = dashboard._build()
    assert layout is not None
