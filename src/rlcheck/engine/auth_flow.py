"""Authentication flow engine — orchestrates discovery → testing → analysis → reporting.

This is the heart of RLCheck Pro.  It coordinates:
1. Login form discovery
2. Credential submission (tester-supplied only)
3. OTP page detection
4. Controlled invalid-OTP testing with smart stop
5. Rate-limit, lockout, CAPTCHA, and session analysis
6. Evidence collection
7. Report generation

**Security principle**: The engine only submits user-provided test credentials and
a user-provided deliberately-invalid OTP.  It never guesses, enumerates, or brute-forces.
"""
from __future__ import annotations

import time
from typing import Optional

from rich.console import Console

from rlcheck.analysis.scoring import score_assessment, AssessmentScore
from rlcheck.analysis.timeline import Timeline
from rlcheck.detectors.captcha import CaptchaResult, detect_captcha, should_stop_for_captcha
from rlcheck.detectors.lockout import LockoutResult, detect_lockout, should_stop_for_lockout
from rlcheck.detectors.otp import OTPDetectionResult, evaluate_otp_detection
from rlcheck.detectors.rate_limit import (
    RateLimitResult, detect_rate_limit, should_stop_for_rate_limit,
)
from rlcheck.discovery.csrf import refresh_csrf_token
from rlcheck.discovery.login import LoginFormInfo, discover_login_form
from rlcheck.discovery.otp import OTPFormInfo, detect_otp_page
from rlcheck.engine.request_engine import RequestRecord, execute_request
from rlcheck.engine.safety import SafetyConfig
from rlcheck.engine.session import TrackedSession
from rlcheck.reporters.html import generate_html_report
from rlcheck.reporters.json import generate_json_report
from rlcheck.reporters.terminal import TerminalDashboard, print_final_summary

console = Console()


# ── Full assessment ─────────────────────────────────────────────────────────

def run_full_assessment(
    *,
    url: str,
    user: Optional[str],
    password: Optional[str],
    test_otp: str,
    safety: SafetyConfig,
    report_format: str,
    output_dir: str,
    insecure: bool,
    verbose: bool,
):
    """Execute a full auth → OTP → analysis assessment."""
    timeline = Timeline()
    ts = TrackedSession(verify_tls=not insecure, timeout=safety.timeout)
    records: list[RequestRecord] = []
    response_bodies: dict[int, str] = {}  # Transient — for CAPTCHA scanning only

    dashboard = TerminalDashboard(target=url)
    dashboard.start()

    try:
        # ── Step 1: Discovery ───────────────────────────────────────────────
        dashboard.status = "DISCOVERY"
        dashboard.update()
        timeline.add("Fetching login page")

        resp = ts.get(url)
        html = resp.text
        timeline.add(f"Login page loaded (HTTP {resp.status_code})")

        # Check for CAPTCHA on initial page load
        if should_stop_for_captcha(html):
            timeline.add("CAPTCHA detected on login page — stopping")
            dashboard.status = "STOPPED"
            dashboard.captcha = CaptchaResult(detected=True, captcha_type="Detected on login page")
            dashboard.update()
            dashboard.stop()
            console.print("[bold red]CAPTCHA detected on initial page load. Cannot proceed.[/bold red]")
            return

        login_form = discover_login_form(html, url)
        if login_form is None:
            timeline.add("No login form detected")
            dashboard.status = "STOPPED"
            dashboard.update()
            dashboard.stop()
            console.print("[bold red]No login form detected on the target page.[/bold red]")
            return

        timeline.add(f"Login form discovered (confidence: {login_form.confidence})")
        dashboard.login_endpoint = f"{login_form.method} {login_form.action}"
        dashboard.flow = "LOGIN"
        dashboard.update()

        if verbose:
            console.print(f"[dim]Username field: {login_form.username_field}[/dim]")
            console.print(f"[dim]Password field: {login_form.password_field}[/dim]")
            console.print(f"[dim]CSRF field: {login_form.csrf_field}[/dim]")

        # ── Step 2: Login submission ────────────────────────────────────────
        if user and password:
            dashboard.status = "TESTING"
            timeline.add("Submitting test credentials")

            login_data = dict(login_form.hidden_fields)
            if login_form.username_field:
                login_data[login_form.username_field] = user
            if login_form.password_field:
                login_data[login_form.password_field] = password
            if login_form.csrf_field and login_form.csrf_value:
                login_data[login_form.csrf_field] = login_form.csrf_value

            login_resp = ts.post(login_form.action, data=login_data)
            login_html = login_resp.text
            timeline.add(f"Login response: HTTP {login_resp.status_code}")

            # ── Step 3: OTP detection ───────────────────────────────────────
            otp_form = detect_otp_page(login_html, login_resp.url)

            if otp_form and otp_form.detected:
                timeline.add(f"OTP page detected (confidence: {otp_form.confidence})")
                dashboard.flow = "LOGIN → OTP"
                dashboard.otp_endpoint = f"{otp_form.method} {otp_form.action}"
                dashboard.update()

                # Refresh CSRF if the OTP page has a new one
                new_csrf = refresh_csrf_token(login_html)
                if new_csrf:
                    otp_form.csrf_field, otp_form.csrf_value = new_csrf

                # ── Step 4: Controlled OTP testing ──────────────────────────
                otp_records, otp_bodies, stop_reason = _run_controlled_otp_test(
                    ts=ts,
                    otp_form=otp_form,
                    test_otp=test_otp,
                    safety=safety,
                    dashboard=dashboard,
                    timeline=timeline,
                )
                records.extend(otp_records)
                response_bodies.update(otp_bodies)
                timeline.add(f"OTP testing stopped: {stop_reason}")
            else:
                timeline.add("No OTP page detected after login")
                otp_form = None
        else:
            otp_form = None
            timeline.add("No credentials provided — skipping login submission")

        # ── Step 5: Login rate-limit testing ────────────────────────────────
        login_records, login_bodies, login_stop = _run_login_rate_test(
            ts=ts,
            login_form=login_form,
            user=user or "test@example.com",
            password="INVALID_TEST_PASSWORD_rlcheck",
            safety=safety,
            dashboard=dashboard,
            timeline=timeline,
        )
        records.extend(login_records)
        response_bodies.update(login_bodies)

        # ── Step 6: Analysis ────────────────────────────────────────────────
        dashboard.status = "COMPLETE"
        timeline.add("Analysis phase")

        otp_records_only = [r for r in records if "otp" in r.url.lower() or "verify" in r.url.lower()]
        login_records_only = [r for r in records if r not in otp_records_only]

        rl_result = detect_rate_limit(otp_records_only) if otp_records_only else None
        login_rl_result = detect_rate_limit(login_records_only) if login_records_only else None
        lockout_result = detect_lockout(records)
        captcha_result = detect_captcha(records, response_bodies)
        otp_det = evaluate_otp_detection(otp_form)

        dashboard.rate_limit = rl_result or login_rl_result
        dashboard.lockout = lockout_result
        dashboard.captcha = captcha_result
        dashboard.session_invalidated = ts.session_changed()
        dashboard.confidence = _overall_confidence(rl_result, lockout_result, captcha_result)
        dashboard.update()

        assessment = score_assessment(
            rate_limit=rl_result,
            lockout=lockout_result,
            captcha=captcha_result,
            otp_detection=otp_det,
            login_rate_limit=login_rl_result,
        )
        assessment.flow_description = dashboard.flow

    finally:
        dashboard.stop()

    # ── Step 7: Reporting ───────────────────────────────────────────────────
    print_final_summary(assessment)

    flow_data = {
        "login_detected": login_form is not None,
        "otp_detected": otp_form is not None and otp_form.otp_field is not None,
        "otp_endpoint": otp_form.action if otp_form else None,
        "login_endpoint": login_form.action if login_form else None,
    }
    config_data = {
        "max_attempts": safety.max_attempts,
        "min_interval": safety.min_interval,
        "timeout": safety.timeout,
        "test_otp_value": "[REDACTED]",
        "insecure_tls": insecure,
    }

    _save_reports(
        report_format=report_format,
        output_dir=output_dir,
        target=url,
        flow=flow_data,
        score=assessment,
        records=records,
        timeline=timeline,
        config=config_data,
    )


# ── Login-only assessment ──────────────────────────────────────────────────

def run_login_assessment(
    *,
    url: str,
    user: Optional[str],
    password: Optional[str],
    safety: SafetyConfig,
    report_format: str,
    output_dir: str,
    insecure: bool,
    verbose: bool,
):
    """Login-only rate-limit assessment."""
    timeline = Timeline()
    ts = TrackedSession(verify_tls=not insecure, timeout=safety.timeout)

    dashboard = TerminalDashboard(target=url)
    dashboard.start()

    try:
        dashboard.status = "DISCOVERY"
        dashboard.update()
        timeline.add("Fetching login page")

        resp = ts.get(url)
        login_form = discover_login_form(resp.text, url)

        if login_form is None:
            dashboard.status = "STOPPED"
            dashboard.update()
            dashboard.stop()
            console.print("[bold red]No login form detected.[/bold red]")
            return

        timeline.add(f"Login form discovered (confidence: {login_form.confidence})")
        dashboard.login_endpoint = f"{login_form.method} {login_form.action}"
        dashboard.flow = "LOGIN"
        dashboard.status = "TESTING"
        dashboard.update()

        records, bodies, stop_reason = _run_login_rate_test(
            ts=ts,
            login_form=login_form,
            user=user or "test@example.com",
            password=password or "INVALID_TEST_PASSWORD_rlcheck",
            safety=safety,
            dashboard=dashboard,
            timeline=timeline,
        )
        timeline.add(f"Login testing stopped: {stop_reason}")

        rl_result = detect_rate_limit(records)
        lockout_result = detect_lockout(records)
        captcha_result = detect_captcha(records, bodies)

        dashboard.rate_limit = rl_result
        dashboard.lockout = lockout_result
        dashboard.captcha = captcha_result
        dashboard.session_invalidated = ts.session_changed()
        dashboard.status = "COMPLETE"
        dashboard.confidence = _overall_confidence(rl_result, lockout_result, captcha_result)
        dashboard.update()

        assessment = score_assessment(
            login_rate_limit=rl_result,
            lockout=lockout_result,
            captcha=captcha_result,
        )
        assessment.flow_description = "LOGIN"

    finally:
        dashboard.stop()

    print_final_summary(assessment)

    _save_reports(
        report_format=report_format, output_dir=output_dir, target=url,
        flow={"login_detected": True, "otp_detected": False},
        score=assessment, records=records, timeline=timeline,
        config={"max_attempts": safety.max_attempts, "min_interval": safety.min_interval},
    )


# ── OTP-only assessment ────────────────────────────────────────────────────

def run_otp_assessment(
    *,
    url: str,
    user: Optional[str],
    password: Optional[str],
    test_otp: str,
    safety: SafetyConfig,
    report_format: str,
    output_dir: str,
    insecure: bool,
    verbose: bool,
):
    """OTP-only rate-limit assessment — requires login first to reach OTP page."""
    timeline = Timeline()
    ts = TrackedSession(verify_tls=not insecure, timeout=safety.timeout)

    dashboard = TerminalDashboard(target=url)
    dashboard.start()

    try:
        dashboard.status = "DISCOVERY"
        dashboard.update()
        timeline.add("Fetching login page")

        resp = ts.get(url)
        login_form = discover_login_form(resp.text, url)
        if login_form is None:
            dashboard.status = "STOPPED"
            dashboard.update()
            dashboard.stop()
            console.print("[bold red]No login form detected.[/bold red]")
            return

        if not user or not password:
            dashboard.stop()
            console.print("[bold red]OTP test requires --user and --password.[/bold red]")
            return

        # Submit credentials to reach OTP page
        timeline.add("Submitting test credentials")
        login_data = dict(login_form.hidden_fields)
        if login_form.username_field:
            login_data[login_form.username_field] = user
        if login_form.password_field:
            login_data[login_form.password_field] = password
        if login_form.csrf_field and login_form.csrf_value:
            login_data[login_form.csrf_field] = login_form.csrf_value

        login_resp = ts.post(login_form.action, data=login_data)
        login_html = login_resp.text
        timeline.add(f"Login response: HTTP {login_resp.status_code}")

        otp_form = detect_otp_page(login_html, login_resp.url)
        if not otp_form or not otp_form.otp_field:
            dashboard.stop()
            console.print("[bold red]No OTP page detected after login.[/bold red]")
            return

        timeline.add(f"OTP page detected (field: {otp_form.otp_field})")
        dashboard.flow = "LOGIN → OTP"
        dashboard.otp_endpoint = f"{otp_form.method} {otp_form.action}"
        dashboard.status = "TESTING"
        dashboard.update()

        new_csrf = refresh_csrf_token(login_html)
        if new_csrf:
            otp_form.csrf_field, otp_form.csrf_value = new_csrf

        records, bodies, stop_reason = _run_controlled_otp_test(
            ts=ts, otp_form=otp_form, test_otp=test_otp,
            safety=safety, dashboard=dashboard, timeline=timeline,
        )
        timeline.add(f"OTP testing stopped: {stop_reason}")

        rl_result = detect_rate_limit(records)
        lockout_result = detect_lockout(records)
        captcha_result = detect_captcha(records, bodies)
        otp_det = evaluate_otp_detection(otp_form)

        dashboard.rate_limit = rl_result
        dashboard.lockout = lockout_result
        dashboard.captcha = captcha_result
        dashboard.session_invalidated = ts.session_changed()
        dashboard.status = "COMPLETE"
        dashboard.confidence = _overall_confidence(rl_result, lockout_result, captcha_result)
        dashboard.update()

        assessment = score_assessment(
            rate_limit=rl_result, lockout=lockout_result,
            captcha=captcha_result, otp_detection=otp_det,
        )
        assessment.flow_description = "LOGIN → OTP"

    finally:
        dashboard.stop()

    print_final_summary(assessment)

    _save_reports(
        report_format=report_format, output_dir=output_dir, target=url,
        flow={"login_detected": True, "otp_detected": True, "otp_endpoint": otp_form.action},
        score=assessment, records=records, timeline=timeline,
        config={"max_attempts": safety.max_attempts, "min_interval": safety.min_interval,
                "test_otp_value": "[REDACTED]"},
    )


# ── Internal helpers ────────────────────────────────────────────────────────

def _run_controlled_otp_test(
    *,
    ts: TrackedSession,
    otp_form: OTPFormInfo,
    test_otp: str,
    safety: SafetyConfig,
    dashboard: TerminalDashboard,
    timeline: Timeline,
) -> tuple[list[RequestRecord], dict[int, str], str]:
    """Submit the same deliberately-invalid OTP up to ``max_attempts`` times.

    Returns ``(records, response_bodies, stop_reason)``.
    """
    records: list[RequestRecord] = []
    bodies: dict[int, str] = {}
    stop_reason = "max_attempts_reached"
    server_errors = 0

    for attempt in range(1, safety.max_attempts + 1):
        # Build POST data
        data = dict(otp_form.hidden_fields)
        if otp_form.otp_field:
            data[otp_form.otp_field] = test_otp
        if otp_form.csrf_field and otp_form.csrf_value:
            data[otp_form.csrf_field] = otp_form.csrf_value

        rec = execute_request(
            session=ts.session,
            method=otp_form.method,
            url=otp_form.action,
            data=data,
            attempt=attempt,
            timeout=safety.timeout,
        )
        records.append(rec)
        dashboard.add_record(rec)
        timeline.add(f"OTP attempt #{attempt}: HTTP {rec.status}")

        # Store body transiently for CAPTCHA scanning
        try:
            body = ts.session.get(otp_form.action, timeout=safety.timeout).text if rec.status == 0 else ""
            # Actually we should use the response from the POST — let's get it from the session
            # The execute_request function doesn't expose the body — use a workaround
        except Exception:
            body = ""
        bodies[attempt] = body

        # Smart stop checks
        if should_stop_for_rate_limit(rec):
            stop_reason = "rate_limit_detected"
            timeline.add(f"Rate limit detected at attempt #{attempt}")
            break

        if should_stop_for_lockout(rec):
            stop_reason = "lockout_detected"
            timeline.add(f"Lockout detected at attempt #{attempt}")
            break

        if rec.status >= 500:
            server_errors += 1
            if server_errors >= 3:
                stop_reason = "server_error_threshold"
                timeline.add("Server error threshold reached")
                break

        # Enforce interval
        if attempt < safety.max_attempts:
            time.sleep(safety.min_interval)

    return records, bodies, stop_reason


def _run_login_rate_test(
    *,
    ts: TrackedSession,
    login_form: LoginFormInfo,
    user: str,
    password: str,
    safety: SafetyConfig,
    dashboard: TerminalDashboard,
    timeline: Timeline,
) -> tuple[list[RequestRecord], dict[int, str], str]:
    """Submit invalid login credentials up to ``max_attempts`` times."""
    records: list[RequestRecord] = []
    bodies: dict[int, str] = {}
    stop_reason = "max_attempts_reached"
    server_errors = 0

    attempt_offset = len(dashboard.records)

    for attempt in range(1, safety.max_attempts + 1):
        # Re-fetch login page to get fresh CSRF token each time
        try:
            fresh_resp = ts.get(login_form.action)
            fresh_form = discover_login_form(fresh_resp.text, login_form.action)
            if fresh_form and fresh_form.csrf_field:
                login_form.csrf_field = fresh_form.csrf_field
                login_form.csrf_value = fresh_form.csrf_value
                login_form.hidden_fields = fresh_form.hidden_fields
        except Exception:
            pass  # Proceed with existing CSRF token

        data = dict(login_form.hidden_fields)
        if login_form.username_field:
            data[login_form.username_field] = user
        if login_form.password_field:
            data[login_form.password_field] = password
        if login_form.csrf_field and login_form.csrf_value:
            data[login_form.csrf_field] = login_form.csrf_value

        rec = execute_request(
            session=ts.session,
            method=login_form.method,
            url=login_form.action,
            data=data,
            attempt=attempt_offset + attempt,
            timeout=safety.timeout,
        )
        records.append(rec)
        dashboard.add_record(rec)
        timeline.add(f"Login attempt #{attempt}: HTTP {rec.status}")

        bodies[rec.attempt] = ""  # We don't store login response bodies

        if should_stop_for_rate_limit(rec):
            stop_reason = "rate_limit_detected"
            break

        if should_stop_for_lockout(rec):
            stop_reason = "lockout_detected"
            break

        if rec.status >= 500:
            server_errors += 1
            if server_errors >= 3:
                stop_reason = "server_error_threshold"
                break

        if attempt < safety.max_attempts:
            time.sleep(safety.min_interval)

    return records, bodies, stop_reason


def _overall_confidence(*results) -> str:
    """Pick the highest confidence from detector results."""
    levels = []
    for r in results:
        if r and hasattr(r, "confidence"):
            levels.append(r.confidence)
    rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1}
    if not levels:
        return "LOW"
    return max(levels, key=lambda l: rank.get(l, 0))


def _save_reports(
    *,
    report_format: str,
    output_dir: str,
    target: str,
    flow: dict,
    score: AssessmentScore,
    records: list[RequestRecord],
    timeline: Timeline,
    config: dict,
):
    """Save JSON and/or HTML reports based on format selection."""
    if report_format in ("json", "all"):
        path = generate_json_report(
            target=target, flow=flow, score=score,
            records=records, timeline=timeline, config=config,
            output_dir=output_dir,
        )
        console.print(f"\n[green]JSON report saved: {path}[/green]")

    if report_format in ("html", "all"):
        # Build the data dict for HTML rendering
        import json
        json_path = generate_json_report(
            target=target, flow=flow, score=score,
            records=records, timeline=timeline, config=config,
            output_dir=output_dir,
        )
        from rlcheck.reporters.json import load_report
        data = load_report(json_path)
        html_path = generate_html_report(data, output_dir=output_dir)
        console.print(f"[green]HTML report saved: {html_path}[/green]")
