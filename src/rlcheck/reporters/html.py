"""HTML report generation — professional, self-contained HTML report.

Uses Jinja2 templating with an embedded stylesheet for a polished,
print-ready security assessment report.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Any, Dict

from jinja2 import Template

from rlcheck import __tool_name__, __version__

_HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ tool }} — Assessment Report</title>
<style>
  :root {
    --bg: #0f172a; --surface: #1e293b; --border: #334155;
    --text: #e2e8f0; --muted: #94a3b8; --accent: #38bdf8;
    --green: #4ade80; --yellow: #facc15; --red: #f87171;
    --orange: #fb923c; --purple: #c084fc;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: var(--bg); color: var(--text); line-height: 1.6;
    padding: 2rem; max-width: 1000px; margin: 0 auto;
  }
  h1 { color: var(--accent); font-size: 1.8rem; margin-bottom: .5rem; }
  h2 {
    color: var(--accent); font-size: 1.3rem; margin: 2rem 0 1rem;
    border-bottom: 1px solid var(--border); padding-bottom: .4rem;
  }
  h3 { color: var(--text); font-size: 1.1rem; margin: 1.2rem 0 .5rem; }
  .subtitle { color: var(--muted); font-size: .9rem; margin-bottom: 2rem; }
  .card {
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 8px; padding: 1.2rem; margin-bottom: 1.2rem;
  }
  .badge {
    display: inline-block; padding: 2px 10px; border-radius: 4px;
    font-weight: 600; font-size: .85rem; text-transform: uppercase;
  }
  .badge-green { background: rgba(74,222,128,.15); color: var(--green); }
  .badge-red { background: rgba(248,113,113,.15); color: var(--red); }
  .badge-yellow { background: rgba(250,204,21,.15); color: var(--yellow); }
  .badge-orange { background: rgba(251,146,60,.15); color: var(--orange); }
  table {
    width: 100%; border-collapse: collapse; margin: .8rem 0;
    font-size: .9rem;
  }
  th, td { padding: .5rem .8rem; text-align: left; border-bottom: 1px solid var(--border); }
  th { color: var(--muted); font-weight: 600; }
  .timeline { list-style: none; padding: 0; }
  .timeline li {
    display: flex; gap: 1rem; padding: .3rem 0;
    border-left: 2px solid var(--border); padding-left: 1rem; margin-left: .5rem;
  }
  .timeline li .ts { color: var(--accent); font-family: monospace; min-width: 70px; }
  .evidence-list { list-style: disc inside; margin: .5rem 0; color: var(--muted); }
  .evidence-list li { margin: .2rem 0; }
  .footer { margin-top: 3rem; color: var(--muted); font-size: .8rem; text-align: center; }
  .disclaimer {
    background: rgba(248,113,113,.08); border: 1px solid rgba(248,113,113,.3);
    border-radius: 6px; padding: 1rem; margin: 1.5rem 0; font-size: .85rem;
  }
</style>
</head>
<body>

<h1>{{ tool }}</h1>
<p class="subtitle">v{{ version }} — Security Assessment Report</p>

<div class="disclaimer">
  ⚠ <strong>AUTHORIZED SECURITY TESTING ONLY</strong> — This report was generated
  during a controlled, low-volume assessment. Findings represent observations made
  during the configured test and should be validated independently.
</div>

<h2>Executive Summary</h2>
<div class="card">
  <p><strong>Target:</strong> {{ target }}</p>
  <p><strong>Date:</strong> {{ generated }}</p>
  <p><strong>Overall Confidence:</strong>
    <span class="badge {% if assessment.overall_confidence == 'HIGH' %}badge-green{% elif assessment.overall_confidence == 'MEDIUM' %}badge-yellow{% else %}badge-orange{% endif %}">
      {{ assessment.overall_confidence }}
    </span>
  </p>
  {% if assessment.flow_description %}
  <p><strong>Flow:</strong> {{ assessment.flow_description }}</p>
  {% endif %}
</div>

<h2>Authentication Flow</h2>
<div class="card">
  <p><strong>Login Detected:</strong> {{ "Yes" if flow.login_detected else "No" }}</p>
  <p><strong>OTP Detected:</strong> {{ "Yes" if flow.otp_detected else "No" }}</p>
  {% if flow.otp_endpoint %}
  <p><strong>OTP Endpoint:</strong> <code>{{ flow.otp_endpoint }}</code></p>
  {% endif %}
  {% if flow.login_endpoint %}
  <p><strong>Login Endpoint:</strong> <code>{{ flow.login_endpoint }}</code></p>
  {% endif %}
</div>

<h2>Findings</h2>
{% for finding in assessment.findings %}
<div class="card">
  <h3>{{ finding.category }}</h3>
  <p>
    <strong>Status:</strong>
    <span class="badge {% if finding.status == 'DETECTED' %}badge-green{% elif finding.status == 'POSSIBLE' %}badge-yellow{% else %}badge-red{% endif %}">
      {{ finding.status }}
    </span>
    &nbsp;
    <strong>Confidence:</strong>
    <span class="badge {% if finding.confidence == 'HIGH' %}badge-green{% elif finding.confidence == 'MEDIUM' %}badge-yellow{% else %}badge-orange{% endif %}">
      {{ finding.confidence }}
    </span>
  </p>
  <p style="margin-top:.6rem"><strong>Risk:</strong> {{ finding.risk_summary }}</p>
  <p><strong>Recommendation:</strong> {{ finding.recommendation }}</p>
  {% if finding.evidence %}
  <p style="margin-top:.6rem"><strong>Evidence:</strong></p>
  <ul class="evidence-list">
    {% for e in finding.evidence %}
    <li>{{ e }}</li>
    {% endfor %}
  </ul>
  {% endif %}
</div>
{% endfor %}

<h2>Evidence Timeline</h2>
<div class="card">
  {% if timeline %}
  <ul class="timeline">
    {% for ev in timeline %}
    <li><span class="ts">{{ ev.timestamp }}</span> {{ ev.event }}</li>
    {% endfor %}
  </ul>
  {% else %}
  <p style="color:var(--muted)">No timeline events recorded.</p>
  {% endif %}
</div>

<h2>Request Evidence</h2>
<div class="card" style="overflow-x:auto">
  <table>
    <thead>
      <tr>
        <th>#</th><th>Time</th><th>Method</th><th>Status</th>
        <th>Elapsed</th><th>Size</th><th>Fingerprint</th>
      </tr>
    </thead>
    <tbody>
    {% for rec in evidence %}
      <tr>
        <td>{{ rec.attempt }}</td>
        <td style="font-family:monospace;font-size:.8rem">{{ rec.timestamp }}</td>
        <td>{{ rec.method }}</td>
        <td><span class="badge {% if rec.status == 429 %}badge-red{% elif rec.status == 401 %}badge-yellow{% elif rec.status == 200 %}badge-green{% else %}badge-orange{% endif %}">{{ rec.status }}</span></td>
        <td>{{ "%.3f"|format(rec.elapsed_s) }}s</td>
        <td>{{ rec.response_size }}</td>
        <td style="font-family:monospace;font-size:.8rem">{{ rec.fingerprint.combined[:8] if rec.fingerprint else '—' }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
</div>

<h2>Test Configuration</h2>
<div class="card">
  <table>
    {% for key, val in config.items() %}
    <tr><td><strong>{{ key }}</strong></td><td>{{ val }}</td></tr>
    {% endfor %}
  </table>
</div>

<div class="footer">
  Generated by {{ tool }} v{{ version }}<br>
  Authorized security assessment — controlled, low-volume testing only.
</div>

</body>
</html>"""


def render_html_report(data: dict) -> str:
    """Render a JSON report dict into a self-contained HTML string."""
    template = Template(_HTML_TEMPLATE)
    return template.render(
        tool=data.get("tool", __tool_name__),
        version=data.get("version", __version__),
        target=data.get("target", ""),
        generated=data.get("generated_utc", datetime.now(timezone.utc).isoformat()),
        flow=data.get("flow", {}),
        assessment=data.get("assessment", {}),
        evidence=data.get("evidence", []),
        timeline=data.get("timeline", []),
        config=data.get("test_configuration", {}),
    )


def generate_html_report(
    data: dict,
    output_dir: str = "reports",
) -> str:
    """Render HTML from report data and write to disk. Return file path."""
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"rlcheck-{ts}.html"
    filepath = os.path.join(output_dir, filename)

    html = render_html_report(data)
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)

    return filepath
