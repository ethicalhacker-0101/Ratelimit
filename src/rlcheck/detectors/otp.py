"""OTP-specific detector — wraps the discovery module with runtime analysis."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

from rlcheck.discovery.otp import OTPFormInfo


@dataclass
class OTPDetectionResult:
    """Result of OTP detection, including runtime analysis."""
    detected: bool = False
    otp_field: Optional[str] = None
    otp_endpoint: Optional[str] = None
    confidence: str = "LOW"
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "detected": self.detected,
            "otp_field": self.otp_field,
            "otp_endpoint": self.otp_endpoint,
            "confidence": self.confidence,
            "evidence": self.evidence,
        }


def evaluate_otp_detection(form_info: Optional[OTPFormInfo]) -> OTPDetectionResult:
    """Convert discovery-layer ``OTPFormInfo`` into a detection result."""
    result = OTPDetectionResult()
    if form_info is None:
        result.evidence.append("No OTP form detected on the page.")
        return result

    result.detected = True
    result.otp_field = form_info.otp_field
    result.otp_endpoint = form_info.action
    result.confidence = form_info.confidence

    if form_info.otp_field:
        result.evidence.append(f"OTP field identified: {form_info.otp_field}")
    if form_info.csrf_field:
        result.evidence.append("CSRF token present on OTP form.")
    if form_info.hidden_fields:
        result.evidence.append(
            f"Hidden fields: {', '.join(form_info.hidden_fields.keys())}"
        )

    return result
