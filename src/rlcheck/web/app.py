"""Flask web dashboard — local-only interface for RLCheck Pro.

Provides:
- A form to configure and start an assessment
- Server-Sent Events (SSE) stream for real-time updates
- A results panel with live detection status

Binds exclusively to 127.0.0.1 for safety.
"""
from __future__ import annotations

import json
import queue
import threading
import time
from typing import Optional

from flask import Flask, Response, render_template_string, request, jsonify

from rlcheck import __tool_name__, __version__
from rlcheck.engine.safety import SafetyConfig, validate_safety

# Global event queue for SSE
_event_queue: queue.Queue = queue.Queue()
_assessment_running = False
_assessment_lock = threading.Lock()


def create_app() -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "rlcheck-local-only"

    @app.route("/")
    def index():
        return render_template_string(_INDEX_HTML, tool=__tool_name__, version=__version__)

    @app.route("/api/start", methods=["POST"])
    def start_assessment():
        global _assessment_running
        with _assessment_lock:
            if _assessment_running:
                return jsonify({"error": "Assessment already running"}), 409
            _assessment_running = True

        data = request.json or {}
        url = data.get("url", "").strip()
        user = data.get("user", "").strip() or None
        password = data.get("password", "").strip() or None
        test_otp = data.get("test_otp", "000000").strip()
        attempts = int(data.get("attempts", 10))
        interval = float(data.get("interval", 2))

        if not url:
            _assessment_running = False
            return jsonify({"error": "URL is required"}), 400

        safety = SafetyConfig(max_attempts=attempts, min_interval=interval)
        ok, msg = validate_safety(safety)
        if not ok:
            _assessment_running = False
            return jsonify({"error": msg}), 400

        # Run assessment in background thread
        thread = threading.Thread(
            target=_run_web_assessment,
            kwargs=dict(
                url=url, user=user, password=password,
                test_otp=test_otp, safety=safety,
            ),
            daemon=True,
        )
        thread.start()

        return jsonify({"status": "started"})

    @app.route("/api/events")
    def events():
        """SSE endpoint for real-time updates."""
        def stream():
            while True:
                try:
                    event = _event_queue.get(timeout=30)
                    yield f"data: {json.dumps(event)}\n\n"
                    if event.get("type") == "complete":
                        break
                except queue.Empty:
                    yield f"data: {json.dumps({'type': 'heartbeat'})}\n\n"

        return Response(stream(), mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    return app


def _emit(event_type: str, **data):
    """Push an event to the SSE queue."""
    _event_queue.put({"type": event_type, **data})


def _run_web_assessment(*, url: str, user: Optional[str], password: Optional[str],
                        test_otp: str, safety: SafetyConfig):
    """Background thread that runs the assessment and emits SSE events."""
    global _assessment_running

    try:
        from rlcheck.engine.session import TrackedSession
        from rlcheck.discovery.login import discover_login_form
        from rlcheck.discovery.otp import detect_otp_page
        from rlcheck.discovery.csrf import refresh_csrf_token
        from rlcheck.engine.request_engine import execute_request
        from rlcheck.detectors.rate_limit import detect_rate_limit, should_stop_for_rate_limit
        from rlcheck.detectors.lockout import detect_lockout, should_stop_for_lockout
        from rlcheck.detectors.captcha import detect_captcha, should_stop_for_captcha

        ts = TrackedSession(verify_tls=True, timeout=safety.timeout)
        records = []
        response_bodies = {}

        _emit("status", message="Fetching login page…", phase="DISCOVERY")

        resp = ts.get(url)
        html = resp.text

        if should_stop_for_captcha(html):
            _emit("captcha", detected=True, message="CAPTCHA detected on login page")
            _emit("complete", message="Assessment stopped — CAPTCHA on initial page")
            return

        login_form = discover_login_form(html, url)
        if login_form is None:
            _emit("error", message="No login form detected")
            _emit("complete", message="Assessment stopped — no login form")
            return

        _emit("discovery", login_endpoint=login_form.action,
              username_field=login_form.username_field,
              confidence=login_form.confidence)

        otp_form = None
        flow = "LOGIN"

        # Login submission
        if user and password:
            _emit("status", message="Submitting credentials…", phase="LOGIN")

            login_data = dict(login_form.hidden_fields)
            if login_form.username_field:
                login_data[login_form.username_field] = user
            if login_form.password_field:
                login_data[login_form.password_field] = password
            if login_form.csrf_field and login_form.csrf_value:
                login_data[login_form.csrf_field] = login_form.csrf_value

            login_resp = ts.post(login_form.action, data=login_data)
            _emit("login_result", status=login_resp.status_code)

            otp_form = detect_otp_page(login_resp.text, login_resp.url)
            if otp_form and otp_form.otp_field:
                flow = "LOGIN → OTP"
                _emit("otp_detected", endpoint=otp_form.action,
                      field=otp_form.otp_field, confidence=otp_form.confidence)

                new_csrf = refresh_csrf_token(login_resp.text)
                if new_csrf:
                    otp_form.csrf_field, otp_form.csrf_value = new_csrf

                # Controlled OTP testing
                _emit("status", message="Starting controlled OTP test…", phase="OTP_TEST")
                server_errors = 0
                for attempt in range(1, safety.max_attempts + 1):
                    data_otp = dict(otp_form.hidden_fields)
                    if otp_form.otp_field:
                        data_otp[otp_form.otp_field] = test_otp
                    if otp_form.csrf_field and otp_form.csrf_value:
                        data_otp[otp_form.csrf_field] = otp_form.csrf_value

                    rec = execute_request(
                        session=ts.session, method=otp_form.method,
                        url=otp_form.action, data=data_otp,
                        attempt=attempt, timeout=safety.timeout,
                    )
                    records.append(rec)
                    _emit("attempt", attempt=attempt, status=rec.status,
                          elapsed=round(rec.elapsed, 3), size=rec.response_size,
                          fingerprint=rec.fingerprint.combined_hash[:8] if rec.fingerprint else "")

                    if should_stop_for_rate_limit(rec):
                        _emit("rate_limit", detected=True, attempt=attempt)
                        break
                    if should_stop_for_lockout(rec):
                        _emit("lockout", detected=True, attempt=attempt)
                        break
                    if rec.status >= 500:
                        server_errors += 1
                        if server_errors >= 3:
                            _emit("error", message="Server error threshold reached")
                            break

                    if attempt < safety.max_attempts:
                        time.sleep(safety.min_interval)

        # Analysis
        rl = detect_rate_limit(records) if records else None
        lo = detect_lockout(records) if records else None
        ca = detect_captcha(records, response_bodies) if records else None

        _emit("results",
              flow=flow,
              rate_limit={"detected": rl.detected if rl else False,
                          "confidence": rl.confidence if rl else "N/A",
                          "retry_after": rl.retry_after if rl else None},
              lockout={"detected": lo.detected if lo else False,
                       "possible": lo.possible if lo else False},
              captcha={"detected": ca.detected if ca else False},
              session_changed=ts.session_changed(),
              total_attempts=len(records))

        _emit("complete", message="Assessment complete")

    except Exception as e:
        _emit("error", message=str(e))
        _emit("complete", message="Assessment failed")
    finally:
        _assessment_running = False


# ── HTML Template ───────────────────────────────────────────────────────────

_INDEX_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ tool }} — Web Dashboard</title>
<style>
  :root {
    --bg: #0a0e1a; --surface: #131a2e; --surface2: #1a2340;
    --border: #2a3555; --text: #e0e6f0; --muted: #8892a8;
    --accent: #38bdf8; --accent2: #818cf8; --green: #4ade80;
    --yellow: #facc15; --red: #f87171; --orange: #fb923c;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: var(--bg); color: var(--text);
    min-height: 100vh; padding: 0;
  }
  .header {
    background: linear-gradient(135deg, var(--surface), var(--surface2));
    border-bottom: 1px solid var(--border);
    padding: 1.5rem 2rem; display: flex; align-items: center; gap: 1rem;
  }
  .header h1 { font-size: 1.5rem; color: var(--accent); }
  .header .ver { color: var(--muted); font-size: .85rem; }
  .main { display: grid; grid-template-columns: 380px 1fr; min-height: calc(100vh - 70px); }
  .sidebar {
    background: var(--surface); border-right: 1px solid var(--border);
    padding: 1.5rem; overflow-y: auto;
  }
  .content { padding: 1.5rem; overflow-y: auto; }
  label { display: block; color: var(--muted); font-size: .85rem; margin-bottom: .3rem; margin-top: 1rem; }
  input[type="text"], input[type="number"], input[type="password"] {
    width: 100%; padding: .6rem .8rem; border-radius: 6px;
    border: 1px solid var(--border); background: var(--bg); color: var(--text);
    font-size: .95rem; outline: none; transition: border-color .2s;
  }
  input:focus { border-color: var(--accent); }
  .btn {
    display: block; width: 100%; padding: .75rem; margin-top: 1.5rem;
    border: none; border-radius: 8px; cursor: pointer;
    font-size: 1rem; font-weight: 600; transition: all .2s;
    background: linear-gradient(135deg, var(--accent), var(--accent2));
    color: #fff; text-transform: uppercase; letter-spacing: .05em;
  }
  .btn:hover { opacity: .9; transform: translateY(-1px); }
  .btn:disabled { opacity: .5; cursor: not-allowed; transform: none; }
  .disclaimer {
    margin-top: 1.5rem; padding: .8rem; border-radius: 6px;
    background: rgba(248,113,113,.08); border: 1px solid rgba(248,113,113,.2);
    font-size: .8rem; color: var(--orange);
  }
  .panel {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 1.2rem; margin-bottom: 1rem;
  }
  .panel h3 { color: var(--accent); font-size: 1rem; margin-bottom: .8rem; }
  .stat { display: flex; justify-content: space-between; padding: .4rem 0; border-bottom: 1px solid var(--border); }
  .stat:last-child { border-bottom: none; }
  .stat .label { color: var(--muted); }
  .badge {
    display: inline-block; padding: 2px 8px; border-radius: 4px;
    font-weight: 600; font-size: .8rem;
  }
  .badge-green { background: rgba(74,222,128,.15); color: var(--green); }
  .badge-red { background: rgba(248,113,113,.15); color: var(--red); }
  .badge-yellow { background: rgba(250,204,21,.15); color: var(--yellow); }
  #attempts-table { width: 100%; border-collapse: collapse; margin-top: .8rem; font-size: .85rem; }
  #attempts-table th { color: var(--muted); font-weight: 600; text-align: left; padding: .4rem .6rem; }
  #attempts-table td { padding: .4rem .6rem; border-top: 1px solid var(--border); }
  #log { margin-top: 1rem; padding: .8rem; background: var(--bg); border-radius: 6px;
         font-family: monospace; font-size: .8rem; color: var(--muted);
         max-height: 200px; overflow-y: auto; }
  #log div { padding: .15rem 0; }
  .phase { color: var(--accent); font-weight: 600; }
</style>
</head>
<body>

<div class="header">
  <h1>🔐 {{ tool }}</h1>
  <span class="ver">v{{ version }} — Web Dashboard</span>
</div>

<div class="main">
  <div class="sidebar">
    <label>Target URL</label>
    <input type="text" id="url" placeholder="https://authorized-target/login">

    <label>Username / Email</label>
    <input type="text" id="user" placeholder="test@example.com">

    <label>Password</label>
    <input type="password" id="password" placeholder="Test password">

    <label>Test OTP (known-invalid)</label>
    <input type="text" id="test_otp" value="000000">

    <label>Max Attempts</label>
    <input type="number" id="attempts" value="10" min="1" max="50">

    <label>Interval (seconds)</label>
    <input type="number" id="interval" value="2" min="1" max="30" step="0.5">

    <button class="btn" id="startBtn" onclick="startAssessment()">Start Assessment</button>

    <div class="disclaimer">
      ⚠ <strong>AUTHORIZED SECURITY TESTING ONLY</strong><br>
      Controlled request mode — low-volume, non-destructive.
    </div>
  </div>

  <div class="content">
    <div class="panel" id="status-panel">
      <h3>Status</h3>
      <div class="stat"><span class="label">Phase</span><span id="phase" class="phase">IDLE</span></div>
      <div class="stat"><span class="label">Flow</span><span id="flow">—</span></div>
      <div class="stat"><span class="label">Attempts</span><span id="attempt-count">0</span></div>
    </div>

    <div class="panel">
      <h3>Detection Results</h3>
      <div class="stat"><span class="label">Rate Limit</span><span id="rl">—</span></div>
      <div class="stat"><span class="label">Lockout</span><span id="lo">—</span></div>
      <div class="stat"><span class="label">CAPTCHA</span><span id="cap">—</span></div>
      <div class="stat"><span class="label">Session Changed</span><span id="sess">—</span></div>
      <div class="stat"><span class="label">Confidence</span><span id="conf">—</span></div>
    </div>

    <div class="panel">
      <h3>Attempt Monitor</h3>
      <table id="attempts-table">
        <thead><tr><th>#</th><th>Status</th><th>Time</th><th>Size</th><th>FP</th></tr></thead>
        <tbody id="attempts-body"></tbody>
      </table>
    </div>

    <div class="panel">
      <h3>Event Log</h3>
      <div id="log"></div>
    </div>
  </div>
</div>

<script>
let evtSource = null;
let attemptCount = 0;

function startAssessment() {
  const btn = document.getElementById('startBtn');
  btn.disabled = true;
  btn.textContent = 'RUNNING…';
  attemptCount = 0;
  document.getElementById('attempts-body').innerHTML = '';
  document.getElementById('log').innerHTML = '';

  const payload = {
    url: document.getElementById('url').value,
    user: document.getElementById('user').value,
    password: document.getElementById('password').value,
    test_otp: document.getElementById('test_otp').value,
    attempts: document.getElementById('attempts').value,
    interval: document.getElementById('interval').value,
  };

  fetch('/api/start', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(payload),
  }).then(r => r.json()).then(data => {
    if (data.error) {
      addLog('Error: ' + data.error);
      btn.disabled = false; btn.textContent = 'START ASSESSMENT';
      return;
    }
    listenSSE();
  }).catch(err => {
    addLog('Request failed: ' + err);
    btn.disabled = false; btn.textContent = 'START ASSESSMENT';
  });
}

function listenSSE() {
  evtSource = new EventSource('/api/events');
  evtSource.onmessage = function(e) {
    const d = JSON.parse(e.data);
    handleEvent(d);
  };
  evtSource.onerror = function() {
    evtSource.close();
  };
}

function handleEvent(d) {
  const t = d.type;

  if (t === 'status') {
    document.getElementById('phase').textContent = d.phase || d.message;
    addLog(d.message);
  } else if (t === 'discovery') {
    addLog('Login form found: ' + d.login_endpoint + ' (confidence: ' + d.confidence + ')');
  } else if (t === 'login_result') {
    addLog('Login response: HTTP ' + d.status);
  } else if (t === 'otp_detected') {
    document.getElementById('flow').textContent = 'LOGIN → OTP';
    addLog('OTP detected: ' + d.endpoint + ' (field: ' + d.field + ')');
  } else if (t === 'attempt') {
    attemptCount++;
    document.getElementById('attempt-count').textContent = attemptCount;
    const tbody = document.getElementById('attempts-body');
    const cls = d.status === 429 ? 'badge-red' : d.status === 401 ? 'badge-yellow' : 'badge-green';
    tbody.innerHTML += '<tr><td>' + d.attempt + '</td><td><span class="badge ' + cls + '">' +
      d.status + '</span></td><td>' + d.elapsed + 's</td><td>' + d.size +
      '</td><td style="font-family:monospace">' + d.fingerprint + '</td></tr>';
    // Auto-scroll
    tbody.parentElement.scrollTop = tbody.parentElement.scrollHeight;
  } else if (t === 'rate_limit') {
    document.getElementById('rl').innerHTML = '<span class="badge badge-green">DETECTED</span>';
    addLog('Rate limit detected at attempt #' + d.attempt);
  } else if (t === 'lockout') {
    document.getElementById('lo').innerHTML = '<span class="badge badge-green">DETECTED</span>';
    addLog('Lockout detected at attempt #' + d.attempt);
  } else if (t === 'captcha') {
    document.getElementById('cap').innerHTML = '<span class="badge badge-green">DETECTED</span>';
    addLog('CAPTCHA detected');
  } else if (t === 'results') {
    document.getElementById('flow').textContent = d.flow;
    const rl = d.rate_limit;
    document.getElementById('rl').innerHTML = rl.detected ?
      '<span class="badge badge-green">DETECTED</span>' :
      '<span class="badge badge-red">NOT DETECTED</span>';
    document.getElementById('conf').textContent = rl.confidence || '—';
    const lo = d.lockout;
    if (lo.detected) {
      document.getElementById('lo').innerHTML = '<span class="badge badge-green">DETECTED</span>';
    } else if (lo.possible) {
      document.getElementById('lo').innerHTML = '<span class="badge badge-yellow">POSSIBLE</span>';
    } else {
      document.getElementById('lo').innerHTML = '<span class="badge badge-red">NOT DETECTED</span>';
    }
    document.getElementById('cap').innerHTML = d.captcha.detected ?
      '<span class="badge badge-green">DETECTED</span>' :
      '<span class="badge badge-red">NOT DETECTED</span>';
    document.getElementById('sess').textContent = d.session_changed ? 'YES' : 'NO';
  } else if (t === 'error') {
    addLog('⚠ ' + d.message);
  } else if (t === 'complete') {
    document.getElementById('phase').textContent = 'COMPLETE';
    addLog('✓ ' + d.message);
    if (evtSource) evtSource.close();
    const btn = document.getElementById('startBtn');
    btn.disabled = false; btn.textContent = 'START ASSESSMENT';
  }
}

function addLog(msg) {
  const log = document.getElementById('log');
  const ts = new Date().toLocaleTimeString();
  log.innerHTML += '<div><span style="color:var(--accent)">' + ts + '</span>  ' + msg + '</div>';
  log.scrollTop = log.scrollHeight;
}
</script>
</body>
</html>"""
