# cors-scanner

**Zero-dependency Python 3 CORS misconfiguration scanner.**  
Detects reflected origins, null-origin bypass, subdomain/suffix/no-separator regex bypasses, and credential leakage — all with the standard library only.

---

## What are CORS Misconfigurations?

Cross-Origin Resource Sharing (CORS) lets servers declare which external origins may read their responses. A misconfigured CORS policy can allow an attacker-controlled website to make **authenticated requests** to an API on behalf of a logged-in victim and read the response — effectively bypassing the Same-Origin Policy.

**Why it matters:**
- An attacker hosts a page at `evil.com`
- The victim visits `evil.com` while logged in to `api.bank.com`
- If `api.bank.com` reflects `evil.com` in `Access-Control-Allow-Origin` **and** sends `Access-Control-Allow-Credentials: true`, the attacker's JavaScript can read the authenticated API response
- Account takeover, data exfiltration, CSRF amplification

---

## Probe Table

| # | Probe | Origin Sent | Risk if Reflected |
|---|-------|-------------|-------------------|
| 1 | Arbitrary origin reflection | `https://evil.com` | HIGH / CRITICAL |
| 2 | Null origin reflection | `null` | HIGH / CRITICAL — sandboxed iframes bypass |
| 3 | Subdomain prefix bypass | `https://<target>.evil.com` | HIGH / CRITICAL — weak `endsWith` regex |
| 4 | TLD suffix bypass | `https://evil.com.<target>` | HIGH / CRITICAL — weak `startsWith` regex |
| 5 | No-separator bypass | `https://<target>evil.com` | HIGH / CRITICAL — missing `$` anchor in regex |

**Severity classification:**

| Severity | Condition |
|----------|-----------|
| `CRITICAL` | Origin reflected **and** `Access-Control-Allow-Credentials: true` |
| `HIGH` | Origin reflected, no credentials header |
| `INFO` | Wildcard `ACAO: *` (unauthenticated resources exposed) |
| `PASS` | Origin not reflected |

---

## Installation

No dependencies. Requires **Python 3.10+**.

```bash
git clone https://github.com/G4MEOVER18/cors-scanner.git
cd cors-scanner
python cors_scanner.py --help
```

---

## Usage

```
usage: cors_scanner [-h] [--json] [--cookies COOKIE_STRING] [--method METHOD] url

positional arguments:
  url                   Target URL to scan

options:
  -h, --help            show this help message and exit
  --json                Output results as JSON (machine-readable)
  --cookies COOKIE_STRING
                        Session cookie string, e.g. "session=abc123; csrf=xyz"
  --method METHOD       HTTP method for main request (default: GET).
                        POST/PUT/DELETE also triggers an OPTIONS preflight probe.
```

### Examples

```bash
# Basic scan
python cors_scanner.py https://api.example.com/v1/user

# Authenticated scan (pass session cookie)
python cors_scanner.py https://api.example.com/v1/user \
    --cookies "session=abc123def456; csrf=xyz789"

# Machine-readable JSON output (e.g. for CI pipelines)
python cors_scanner.py https://api.example.com/v1/user --json

# Test POST endpoint + OPTIONS preflight
python cors_scanner.py https://api.example.com/v1/data --method POST

# Chain into CI: exit code 1 on CRITICAL/HIGH
python cors_scanner.py https://api.example.com/v1/user || echo "CORS issue found!"
```

---

## Example Output

```
  ╔═══════════════════════════════════════╗
  ║       CORS Misconfiguration Scanner   ║
  ║       github.com/G4MEOVER18           ║
  ╚═══════════════════════════════════════╝

  Target : https://api.vulnerable-app.com/user
  Running 5 probes × 1 method(s)…

  [CRITICAL]  Arbitrary origin reflection
              Origin sent : https://evil.com
              ACAO        : https://evil.com
              ACAC        : true
              Origin reflected AND Access-Control-Allow-Credentials: true —
              authenticated requests from 'https://evil.com' are permitted!

  [PASS    ]  Null origin reflection
              Origin not reflected

  [HIGH    ]  Subdomain prefix bypass
              Origin sent : https://api.vulnerable-app.com.evil.com
              ACAO        : https://api.vulnerable-app.com.evil.com
              Origin 'https://api.vulnerable-app.com.evil.com' is reflected in ACAO without credentials

  [PASS    ]  TLD suffix bypass
              Origin not reflected

  [PASS    ]  No-separator bypass
              Origin not reflected

  ──────────────────────────────────────────────────
  1 CRITICAL finding(s)!
  1 HIGH finding(s)!
  ──────────────────────────────────────────────────
```

### JSON output (`--json`)

```json
{
  "target": "https://api.vulnerable-app.com/user",
  "method": "GET",
  "probes_run": 5,
  "summary": {
    "CRITICAL": 1,
    "HIGH": 1,
    "INFO": 0,
    "PASS": 3,
    "ERROR": 0
  },
  "findings": [
    {
      "probe_id": "reflected_evil",
      "probe_name": "Arbitrary origin reflection",
      "origin_sent": "https://evil.com",
      "severity": "CRITICAL",
      "status": 200,
      "acao": "https://evil.com",
      "acac": "true",
      "message": "Origin reflected AND Access-Control-Allow-Credentials: true ...",
      "method": "GET"
    }
  ]
}
```

---

## Legal Disclaimer

This tool is intended for **authorized security testing only**. Only scan systems you own or have explicit written permission to test. Unauthorized scanning may violate computer crime laws in your jurisdiction.

---

## Contributing

Issues and pull requests are welcome. Please keep the zero-dependency constraint — stdlib only.

---

## Donations

If this tool saved you time, consider a donation:

**Bitcoin:** `39vZWmnUwDReQ15BwqQXzyqVQ6U8LardEf`
**PayPal:** [paypal.me/Freakbank1](https://paypal.me/Freakbank1)

---

## License

MIT License — Copyright (c) 2026 Yanis Ameseder. See [LICENSE](LICENSE).
