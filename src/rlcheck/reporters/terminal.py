"""Rich terminal reporter — real-time live dashboard.

Uses the Rich library to render a continuously-updating dashboard showing:
- Target info & auth flow
- OTP attempt monitor table
- Detection results panel
- Confidence score
"""
from __future__ import annotations

from typing import List, Optional

from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from rlcheck import __tool_name__
from rlcheck.engine.request_engine import RequestRecord
from rlcheck.detectors.rate_limit import RateLimitResult
from rlcheck.detectors.lockout import LockoutResult
from rlcheck.detectors.captcha import CaptchaResult
from rlcheck.analysis.scoring import AssessmentScore

console = Console()


class TerminalDashboard:
    """Live terminal dashboard powered by Rich."""

    def __init__(
        self,
        target: str,
        flow: str = "",
        login_endpoint: str = "",
        otp_endpoint: str = "",
    ):
        self.target = target
        self.flow = flow or "DISCOVERY"
        self.login_endpoint = login_endpoint
        self.otp_endpoint = otp_endpoint
        self.status = "INITIALIZING"
        self.records: List[RequestRecord] = []
        self.rate_limit: Optional[RateLimitResult] = None
        self.lockout: Optional[LockoutResult] = None
        self.captcha: Optional[CaptchaResult] = None
        self.session_invalidated: Optional[bool] = None
        self.confidence = "—"
        self.retry_after: Optional[str] = None
        self._live: Optional[Live] = None

    def start(self):
        """Start the live display."""
        self._live = Live(
            self._build(),
            console=console,
            refresh_per_second=4,
            transient=False,
        )
        self._live.start()

    def stop(self):
        """Stop the live display."""
        if self._live:
            self._live.stop()

    def update(self):
        """Refresh the dashboard with current state."""
        if self._live:
            self._live.update(self._build())

    def add_record(self, record: RequestRecord):
        """Add a request record and refresh."""
        self.records.append(record)
        self.update()

    # ── Layout builder ──────────────────────────────────────────────────────

    def _build(self):
        """Build the full dashboard layout."""
        parts = []

        # Header
        header = Text()
        header.append(f"{__tool_name__}\n", style="bold bright_cyan")
        header.append("─" * 48 + "\n\n", style="dim")
        header.append(f"Target       : {self.target}\n")
        header.append(f"Flow         : {self.flow}\n")
        header.append(f"Status       : {self._status_style()}\n")

        if self.login_endpoint:
            header.append(f"\nLogin Endpoint\n  {self.login_endpoint}\n")
        if self.otp_endpoint:
            header.append(f"\nOTP Endpoint\n  {self.otp_endpoint}\n")

        parts.append(Panel(header, border_style="bright_cyan", title="Target Info"))

        # Attempt monitor table
        if self.records:
            table = Table(
                title="Attempt Monitor",
                show_header=True,
                header_style="bold",
                border_style="dim",
                expand=True,
            )
            table.add_column("Attempt", justify="right", width=8)
            table.add_column("Response", justify="center", width=10)
            table.add_column("Time", justify="right", width=10)
            table.add_column("Size", justify="right", width=10)
            table.add_column("Fingerprint", width=14)

            for rec in self.records[-20:]:  # Show last 20 rows
                status_style = self._status_code_style(rec.status)
                fp_short = rec.fingerprint.combined_hash[:8] if rec.fingerprint else "—"
                table.add_row(
                    f"{rec.attempt:02d}",
                    Text(str(rec.status), style=status_style),
                    f"{rec.elapsed:.2f}s",
                    str(rec.response_size),
                    fp_short,
                )
            parts.append(table)

        # Detection results
        det = Text()
        det.append("─" * 48 + "\n\n", style="dim")

        rl_status = self._detection_str(self.rate_limit)
        det.append(f"Rate Limit       : {rl_status}\n")

        if self.retry_after or (self.rate_limit and self.rate_limit.retry_after):
            ra = self.retry_after or (self.rate_limit.retry_after if self.rate_limit else "—")
            det.append(f"Retry-After      : {ra}\n")

        lo_status = "—"
        if self.lockout:
            if self.lockout.detected:
                lo_status = "DETECTED"
            elif self.lockout.possible:
                lo_status = "POSSIBLE"
            else:
                lo_status = "NOT DETECTED"
        det.append(f"Lockout          : {lo_status}\n")

        cap_status = "NOT DETECTED"
        if self.captcha and self.captcha.detected:
            cap_status = f"DETECTED ({self.captcha.captcha_type})"
        det.append(f"CAPTCHA          : {cap_status}\n")

        si = "—"
        if self.session_invalidated is True:
            si = "YES"
        elif self.session_invalidated is False:
            si = "NO"
        det.append(f"Session Invalid  : {si}\n\n")
        det.append(f"Confidence       : {self.confidence}\n")

        parts.append(Panel(det, border_style="bright_cyan", title="Detection Results"))

        # Combine
        output = Text()
        for part in parts:
            # We use console.print to render panels; instead we return a group
            pass

        from rich.console import Group
        return Group(*parts)

    def _status_style(self) -> Text:
        style_map = {
            "INITIALIZING": "dim",
            "DISCOVERY": "yellow",
            "TESTING": "bold yellow",
            "COMPLETE": "bold green",
            "STOPPED": "bold red",
        }
        return Text(self.status, style=style_map.get(self.status, ""))

    @staticmethod
    def _status_code_style(code: int) -> str:
        if code == 200:
            return "green"
        elif code == 401:
            return "yellow"
        elif code == 429:
            return "bold red"
        elif code == 403:
            return "red"
        elif code == 423:
            return "bold magenta"
        elif code >= 500:
            return "bold red"
        return ""

    @staticmethod
    def _detection_str(result: Optional[RateLimitResult]) -> str:
        if result is None:
            return "—"
        if result.detected:
            return "DETECTED"
        return "NOT DETECTED"


def print_final_summary(score: AssessmentScore):
    """Print a static summary after the live dashboard stops."""
    console.print()
    console.print(Panel(
        Text("Assessment Complete", style="bold green"),
        border_style="green",
    ))

    for finding in score.findings:
        status_style = "green" if finding.status == "DETECTED" else "yellow"
        if finding.status == "NOT DETECTED":
            status_style = "red"

        console.print(f"\n[bold]{finding.category}[/bold]")
        console.print("─" * 40)
        console.print(f"  Status      : [{status_style}]{finding.status}[/{status_style}]")
        console.print(f"  Confidence  : {finding.confidence}")
        console.print(f"  Risk        : {finding.risk_summary}")
        console.print(f"  Recommend   : {finding.recommendation}")
        if finding.evidence:
            console.print("  Evidence:")
            for e in finding.evidence[:5]:
                console.print(f"    • {e}")

    console.print(f"\n[bold]Overall Confidence: {score.overall_confidence}[/bold]")
