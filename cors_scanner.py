#!/usr/bin/env python3
"""
cors_scanner.py — CORS Misconfiguration Scanner
Zero external dependencies. Uses only Python stdlib.

Author : G4MEOVER18
License: MIT
"""

import argparse
import json
import ssl
import sys
import urllib.parse
import urllib.request
from typing import Optional

# ── ANSI colour helpers ────────────────────────────────────────────────────────
RESET  = "\033[0m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
BOLD   = "\033[1m"

def _c(text: str, colour: str) -> str:
    """Wrap text in ANSI colour codes (stripped when stdout is not a TTY)."""
    if not sys.stdout.isatty():
        return text
    return f"{colour}{text}{RESET}"


# ── Probe definitions ──────────────────────────────────────────────────────────
def build_probes(target_domain: str) -> list[dict]:
    """Return the list of Origin probes to send."""
    return [
        {
            "id":   "reflected_evil",
            "name": "Arbitrary origin reflection",
            "origin": "https://evil.com",
            "desc": "Server reflects any arbitrary origin",
        },
        {
            "id":   "null_origin",
            "name": "Null origin reflection",
            "origin": "null",
            "desc": "Server allows null origin (e.g. sandboxed iframes)",
        },
        {
            "id":   "subdomain_prefix",
            "name": "Subdomain prefix bypass",
            "origin": f"https://{target_domain}.evil.com",
            "desc": "Weak regex matches target domain as subdomain of attacker",
        },
        {
            "id":   "tld_suffix",
            "name": "TLD suffix bypass",
            "origin": f"https://evil.com.{target_domain}",
            "desc": "Weak regex matches target domain as suffix of attacker",
        },
        {
            "id":   "no_separator",
            "name": "No-separator bypass",
            "origin": f"https://{target_domain}evil.com",
            "desc": "Missing separator in regex allows prefix-match bypass",
        },
    ]


# ── HTTP helpers ───────────────────────────────────────────────────────────────
def _make_ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def send_request(
    url: str,
    method: str,
    origin: str,
    cookies: Optional[str],
    timeout: int = 10,
) -> tuple[int, dict]:
    """
    Send *method* request with the given Origin header.
    For OPTIONS (preflight) the request is always OPTIONS regardless of --method.
    Returns (status_code, response_headers_dict).
    """
    headers = {
        "Origin": origin,
        "User-Agent": "cors-scanner/1.0 (https://github.com/G4MEOVER18/cors-scanner)",
    }
    if cookies:
        headers["Cookie"] = cookies

    if method.upper() == "OPTIONS":
        headers["Access-Control-Request-Method"] = "POST"
        headers["Access-Control-Request-Headers"] = "Content-Type"

    req = urllib.request.Request(url, headers=headers, method=method.upper())
    ctx = _make_ssl_ctx()

    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            return resp.status, dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, dict(exc.headers)
    except Exception as exc:
        return 0, {"_error": str(exc)}


# ── Analysis ───────────────────────────────────────────────────────────────────
def analyse(probe: dict, origin_sent: str, status: int, headers: dict) -> dict:
    """
    Evaluate response headers for a single probe.
    Returns a result dict with severity and details.
    """
    if "_error" in headers:
        return {
            "probe_id":    probe["id"],
            "probe_name":  probe["name"],
            "origin_sent": origin_sent,
            "severity":    "ERROR",
            "status":      status,
            "acao":        None,
            "acac":        None,
            "message":     headers["_error"],
        }

    # Header names are case-insensitive; normalise to lower-case keys
    lc = {k.lower(): v for k, v in headers.items()}
    acao = lc.get("access-control-allow-origin", "")
    acac = lc.get("access-control-allow-credentials", "").strip().lower()

    reflected   = (acao == origin_sent) or (acao == "*")
    credentials = acac == "true"
    wildcard    = acao == "*"

    if wildcard:
        severity = "INFO"
        message  = "Wildcard ACAO (*) — unauthenticated resources exposed"
    elif reflected and credentials:
        severity = "CRITICAL"
        message  = (
            f"Origin reflected AND Access-Control-Allow-Credentials: true — "
            f"authenticated requests from '{origin_sent}' are permitted!"
        )
    elif reflected:
        severity = "HIGH"
        message  = f"Origin '{origin_sent}' is reflected in ACAO without credentials"
    else:
        severity = "PASS"
        message  = "Origin not reflected"

    return {
        "probe_id":    probe["id"],
        "probe_name":  probe["name"],
        "origin_sent": origin_sent,
        "severity":    severity,
        "status":      status,
        "acao":        acao or None,
        "acac":        acac or None,
        "message":     message,
    }


# ── Output helpers ─────────────────────────────────────────────────────────────
SEV_COLOUR = {
    "CRITICAL": RED + BOLD,
    "HIGH":     YELLOW,
    "INFO":     CYAN,
    "PASS":     GREEN,
    "ERROR":    YELLOW,
}

def print_result(r: dict) -> None:
    colour = SEV_COLOUR.get(r["severity"], "")
    tag    = _c(f"[{r['severity']:8s}]", colour)
    print(f"  {tag}  {r['probe_name']}")
    print(f"            Origin sent : {r['origin_sent']}")
    if r["acao"]:
        print(f"            ACAO        : {r['acao']}")
    if r["acac"]:
        print(f"            ACAC        : {r['acac']}")
    print(f"            {r['message']}")
    print()


def print_banner(url: str) -> None:
    print()
    print(_c("  ╔═══════════════════════════════════════╗", CYAN))
    print(_c("  ║       CORS Misconfiguration Scanner   ║", CYAN))
    print(_c("  ║       github.com/G4MEOVER18           ║", CYAN))
    print(_c("  ╚═══════════════════════════════════════╝", CYAN))
    print()
    print(f"  Target : {_c(url, BOLD)}")
    print()


# ── Main scan logic ────────────────────────────────────────────────────────────
def scan(
    url: str,
    method: str = "GET",
    cookies: Optional[str] = None,
    json_output: bool = False,
) -> int:
    """
    Run all probes against *url*.
    Returns exit code: 0 = clean, 1 = CRITICAL/HIGH found.
    """
    parsed = urllib.parse.urlparse(url)
    target_domain = parsed.hostname or ""

    probes  = build_probes(target_domain)
    methods = ["GET"]
    if method.upper() != "GET":
        methods.append("OPTIONS")  # preflight check

    results = []

    if not json_output:
        print_banner(url)
        print(f"  Running {len(probes)} probes × {len(methods)} method(s)…\n")

    for probe in probes:
        for meth in methods:
            status, headers = send_request(url, meth, probe["origin"], cookies)
            r = analyse(probe, probe["origin"], status, headers)
            r["method"] = meth
            results.append(r)
            if not json_output:
                print_result(r)

    # ── Summary ────────────────────────────────────────────────────────────────
    criticals = [r for r in results if r["severity"] == "CRITICAL"]
    highs     = [r for r in results if r["severity"] == "HIGH"]

    if json_output:
        output = {
            "target":    url,
            "method":    method,
            "probes_run": len(results),
            "summary": {
                "CRITICAL": len(criticals),
                "HIGH":     len(highs),
                "INFO":     sum(1 for r in results if r["severity"] == "INFO"),
                "PASS":     sum(1 for r in results if r["severity"] == "PASS"),
                "ERROR":    sum(1 for r in results if r["severity"] == "ERROR"),
            },
            "findings": [r for r in results if r["severity"] not in ("PASS",)],
        }
        print(json.dumps(output, indent=2))
    else:
        divider = "─" * 50
        print(f"  {divider}")
        total_findings = len(criticals) + len(highs)
        if total_findings == 0:
            print(_c("  No HIGH/CRITICAL findings. Target appears safe.", GREEN))
        else:
            if criticals:
                print(_c(f"  {len(criticals)} CRITICAL finding(s)!", RED + BOLD))
            if highs:
                print(_c(f"  {len(highs)} HIGH finding(s)!", YELLOW))
        print(f"  {divider}\n")

    return 1 if (criticals or highs) else 0


# ── Entry point ────────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(
        prog="cors_scanner",
        description="CORS Misconfiguration Scanner — zero external dependencies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cors_scanner.py https://api.example.com/data
  python cors_scanner.py https://api.example.com/data --json
  python cors_scanner.py https://api.example.com/data --cookies "session=abc123"
  python cors_scanner.py https://api.example.com/data --method POST
        """,
    )
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument(
        "--json",
        action="store_true",
        dest="json_output",
        help="Output results as JSON (machine-readable)",
    )
    parser.add_argument(
        "--cookies",
        metavar="COOKIE_STRING",
        default=None,
        help='Session cookie string, e.g. "session=abc123; csrf=xyz"',
    )
    parser.add_argument(
        "--method",
        default="GET",
        metavar="METHOD",
        help="HTTP method to use for main request (default: GET). "
             "Setting POST/PUT/DELETE also triggers an OPTIONS preflight probe.",
    )

    args = parser.parse_args()

    # Basic URL validation
    parsed = urllib.parse.urlparse(args.url)
    if parsed.scheme not in ("http", "https"):
        parser.error("URL must start with http:// or https://")

    exit_code = scan(
        url=args.url,
        method=args.method,
        cookies=args.cookies,
        json_output=args.json_output,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
