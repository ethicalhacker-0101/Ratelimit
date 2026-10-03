# RLCheck Pro

**Real-Time Authentication & OTP Security Assessment Tool**

RLCheck Pro is a controlled, low-volume security assessment tool designed to evaluate authentication flows, rate limiting, and OTP verification mechanisms.

---

## Features

- **Multi-Signal Rate-Limit Detection**: Status codes (429, 403, 423), standard headers (`Retry-After`, `RateLimit-*`), timing analysis, and response body keywords.
- **Account / Session Lockout Analysis**: Detects temporary suspensions, lockout indicators, and state shifts.
- **Anti-Automation & CAPTCHA Detection**: Recognizes reCAPTCHA, hCaptcha, Cloudflare Turnstile, and challenge pages without attempting bypass.
- **Automated Flow Discovery**: Discovers login forms, OTP challenges, and handles CSRF tokens across form transitions.
- **Controlled & Safe Testing**: Enforces hard caps on request volume and minimum request intervals (never brute-forces).
- **Multiple Reporting Formats**:
  - Live Rich terminal dashboard
  - Structured JSON reports
  - Standalone HTML reports
- **Local Web Interface**: Flask-based real-time assessment dashboard with Server-Sent Events (SSE).

---

## Installation

```bash
# Clone the repository
git clone https://github.com/ethicalhacker-0101/Ratelimit.git
cd Ratelimit

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\activate

# Install dependencies and package
pip install -r requirements.txt
pip install -e .
```

---

## CLI Usage

### Full Authentication Flow Assessment
```bash
rlcheck auth https://example.com/login --user testuser --password testpass
```

### Login Rate-Limit Test
```bash
rlcheck login https://example.com/login --user testuser
```

### OTP Rate-Limit Test
```bash
rlcheck otp https://example.com/login --user testuser --password testpass --test-otp 000000
```

### Launch Local Web Dashboard
```bash
rlcheck web --port 8080
```
Open `http://127.0.0.1:8080` in your browser.

### Re-render / Convert Reports
```bash
rlcheck report reports/rlcheck-YYYYMMDD-HHMMSS.json --format html
```

---

## Running Tests

```bash
pytest -v --cov=rlcheck
```

---

## Security & Ethics Notice

RLCheck Pro is intended strictly for authorized security assessments, penetration testing, and defense validation. Controlled request mode is enforced by default to prevent denial of service or disruption.
