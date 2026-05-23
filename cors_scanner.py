#!/usr/bin/env python3
"""
cors_scanner.py — CORS Misconfiguration Scanner
Zero external dependencies. Uses only Python stdlib.

Author : G4MEOVER18
License: MIT
"""

import argparse
import json
import random
import re
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
MAGENTA = "\033[95m"

def _c(text: str, colour: str) -> str:
    """Wrap text in ANSI colour codes (stripped when stdout is not a TTY)."""
    if not sys.stdout.isatty():
        return text
    return f"{colour}{text}{RESET}"


# ── User-Agent rotation ────────────────────────────────────────────────────────
_USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
]

def _random_ua() -> str:
    return random.choice(_USER_AGENTS)


# ── Probe definitions ──────────────────────────────────────────────────────────
def build_probes(target_domain: str, target_scheme: str = "https") -> list[dict]:
    """Return the full list of Origin probes to send."""

    # Determine opposite scheme for protocol-mixing probes
    opposite_scheme = "http" if target_scheme == "https" else "https"

    # Unicode/IDN prefix chars (Ⓔvil-style lookalikes)
    unicode_domain = "ⓔvil.com"  # Ⓔvil.com  (circled latin small letter e)

    probes = [
        # ── Original 5 probes ──────────────────────────────────────────────────
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
        # ── New 8 probes ───────────────────────────────────────────────────────
        {
            "id":   "protocol_mix",
            "name": "HTTP/HTTPS protocol mixing",
            "origin": f"{opposite_scheme}://{target_domain}",
            "desc": f"Target is {target_scheme}, probe uses {opposite_scheme} — checks if scheme is validated",
        },
        {
            "id":   "port_8080",
            "name": "Port-based bypass (8080)",
            "origin": f"https://{target_domain}:8080",
            "desc": "Non-standard port appended to trusted domain",
        },
        {
            "id":   "port_4443",
            "name": "Port-based bypass (4443)",
            "origin": f"https://{target_domain}:4443",
            "desc": "Alternative HTTPS port appended to trusted domain",
        },
        {
            "id":   "unicode_idn",
            "name": "Unicode/IDN lookalike bypass",
            "origin": f"https://{unicode_domain}",
            "desc": "Unicode lookalike domain to bypass naive string comparison",
        },
        {
            "id":   "case_variation",
            "name": "Case variation bypass",
            "origin": f"https://EVIL.COM",
            "desc": "Uppercase domain — checks if server comparison is case-sensitive",
        },
        {
            "id":   "double_encode",
            "name": "Double-encode dot bypass",
            "origin": "https://evil%252ecom",
            "desc": "URL-encoded dot (%252e) to bypass naive pattern matching",
        },
        {
            "id":   "ip_origin",
            "name": "IP address origin",
            "origin": "https://1.2.3.4",
            "desc": "Raw attacker IP as origin — checks if IP origins are blocked",
        },
        {
            "id":   "trusted_sub_prefix_suffix",
            "name": "Trusted-subdomain prefix+suffix combo",
            "origin": f"https://evil.{target_domain}.com",
            "desc": "Trusted domain sandwiched between attacker-controlled labels",
        },
    ]
    return probes


# ── HTTP helpers ───────────────────────────────────────────────────────────────
def _make_ssl_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


def _build_opener(proxy: Optional[str]) -> urllib.request.OpenerDirector:
    """Build an opener that optionally routes through a proxy."""
    handlers: list = [urllib.request.HTTPSHandler(context=_make_ssl_ctx())]
    if proxy:
        proxy_handler = urllib.request.ProxyHandler({
            "http":  proxy,
            "https": proxy,
        })
        handlers.append(proxy_handler)
    return urllib.request.build_opener(*handlers)


def send_request(
    url: str,
    method: str,
    origin: str,
    cookies: Optional[str],
    timeout: int = 10,
    extra_headers: Optional[dict] = None,
    proxy: Optional[str] = None,
) -> tuple[int, dict, bytes]:
    """
    Send *method* request with the given Origin header.
    Returns (status_code, response_headers_dict, response_body_bytes).
    """
    headers = {
        "Origin": origin,
        "User-Agent": _random_ua(),
    }
    if cookies:
        headers["Cookie"] = cookies
    if extra_headers:
        headers.update(extra_headers)

    if method.upper() == "OPTIONS":
        headers["Access-Control-Request-Method"] = "POST"
        headers["Access-Control-Request-Headers"] = "Content-Type"

    req = urllib.request.Request(url, headers=headers, method=method.upper())
    opener = _build_opener(proxy)

    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read(65536)  # max 64 KB for body analysis
            return resp.status, dict(resp.headers), body
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(65536)
        except Exception:
            body = b""
        return exc.code, dict(exc.headers), body
    except Exception as exc:
        return 0, {"_error": str(exc)}, b""


# ── Sensitive data patterns ────────────────────────────────────────────────────
_SENSITIVE_PATTERNS = [
    ("email",       re.compile(rb"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")),
    ("api_key_hex", re.compile(rb"[0-9a-fA-F]{32,}")),
    ("jwt",         re.compile(rb"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+")),
    ("credit_card", re.compile(rb"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b")),
    ("keyword_password",   re.compile(rb'"password"\s*:', re.IGNORECASE)),
    ("keyword_token",      re.compile(rb'"token"\s*:',    re.IGNORECASE)),
    ("keyword_secret",     re.compile(rb'"secret"\s*:',   re.IGNORECASE)),
    ("keyword_private_key",re.compile(rb'"private_key"\s*:', re.IGNORECASE)),
]

def scan_body_for_leakage(body: bytes) -> list[str]:
    """Return list of sensitive pattern names found in response body."""
    found = []
    for name, pattern in _SENSITIVE_PATTERNS:
        if pattern.search(body):
            found.append(name)
    return found


# ── CORS header enumeration ────────────────────────────────────────────────────
_CORS_HEADERS = [
    "access-control-allow-origin",
    "access-control-allow-credentials",
    "access-control-allow-methods",
    "access-control-allow-headers",
    "access-control-expose-headers",
    "access-control-max-age",
    "vary",
]

def extract_cors_headers(headers: dict) -> dict:
    """Return a dict of all CORS-related headers present in the response."""
    lc = {k.lower(): v for k, v in headers.items()}
    return {h: lc[h] for h in _CORS_HEADERS if h in lc}


# ── Header injection bypass ────────────────────────────────────────────────────
_BYPASS_HEADER_SETS = [
    {"X-Forwarded-Host": "evil.com"},
    {"X-Original-Host":  "evil.com"},
    {"X-ProxyUser-Ip":   "evil.com"},
    {"Forwarded":        "host=evil.com"},
    {"X-Host":           "evil.com"},
]

def test_header_bypasses(
    url: str,
    cookies: Optional[str],
    timeout: int,
    proxy: Optional[str] = None,
) -> list[dict]:
    """
    Send requests with a benign Origin but inject common host-override headers.
    Returns findings where the response reflects evil.com or misuses them.
    """
    findings = []
    benign_origin = "https://legitimate.example.com"

    for hset in _BYPASS_HEADER_SETS:
        status, resp_headers, _ = send_request(
            url, "GET", benign_origin, cookies, timeout,
            extra_headers=hset, proxy=proxy,
        )
        if "_error" in resp_headers:
            continue
        lc = {k.lower(): v for k, v in resp_headers.items()}
        acao = lc.get("access-control-allow-origin", "")
        # Flag if ACAO has been set to something suspicious despite benign origin
        if acao and acao not in ("", benign_origin):
            findings.append({
                "injected_headers": hset,
                "acao_returned":    acao,
                "status":           status,
                "message": (
                    f"ACAO changed to '{acao}' when injecting {list(hset.keys())[0]} — "
                    "possible host-header injection"
                ),
            })
    return findings


# ── Preflight bypass ───────────────────────────────────────────────────────────
def test_preflight_bypass(
    url: str,
    origin: str,
    cookies: Optional[str],
    timeout: int,
    proxy: Optional[str] = None,
) -> Optional[dict]:
    """
    Issue an OPTIONS preflight for the given origin.
    Returns a finding dict if dangerous method grants are detected.
    """
    status, headers, _ = send_request(
        url, "OPTIONS", origin, cookies, timeout, proxy=proxy,
    )
    if "_error" in headers:
        return None
    lc = {k.lower(): v for k, v in headers.items()}
    acam = lc.get("access-control-allow-methods", "")
    acao = lc.get("access-control-allow-origin", "")

    dangerous = any(m in acam.upper() for m in ("*", "PUT", "DELETE", "PATCH"))
    reflected  = acao in (origin, "*")

    if reflected and dangerous:
        return {
            "status":  status,
            "acao":    acao,
            "methods": acam,
            "message": (
                f"OPTIONS preflight reflects origin AND allows dangerous methods: {acam}"
            ),
        }
    return None


# ── Analysis ───────────────────────────────────────────────────────────────────
def analyse(
    probe: dict,
    origin_sent: str,
    status: int,
    headers: dict,
    body: bytes,
    url: str,
    cookies: Optional[str],
    timeout: int,
    proxy: Optional[str] = None,
) -> dict:
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
            "cors_headers": {},
            "message":     headers["_error"],
            "body_leakage": [],
            "preflight_bypass": None,
        }

    # Header names are case-insensitive; normalise to lower-case keys
    lc = {k.lower(): v for k, v in headers.items()}
    acao = lc.get("access-control-allow-origin", "")
    acac = lc.get("access-control-allow-credentials", "").strip().lower()

    reflected   = (acao == origin_sent) or (acao == "*")
    credentials = acac == "true"
    wildcard    = acao == "*"

    # Full CORS header enumeration
    cors_headers = extract_cors_headers(headers)

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

    # Body leakage check for vulnerable findings
    body_leakage: list[str] = []
    if severity in ("CRITICAL", "HIGH"):
        body_leakage = scan_body_for_leakage(body)
        if body_leakage:
            severity = "CRITICAL"
            message += f" | Sensitive data in body: {', '.join(body_leakage)}"

    # Preflight bypass check for vulnerable findings
    preflight_bypass = None
    if severity in ("CRITICAL", "HIGH") and origin_sent not in ("null", "*"):
        preflight_bypass = test_preflight_bypass(
            url, origin_sent, cookies, timeout, proxy=proxy,
        )

    return {
        "probe_id":         probe["id"],
        "probe_name":       probe["name"],
        "origin_sent":      origin_sent,
        "severity":         severity,
        "status":           status,
        "acao":             acao or None,
        "acac":             acac or None,
        "cors_headers":     cors_headers,
        "message":          message,
        "body_leakage":     body_leakage,
        "preflight_bypass": preflight_bypass,
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
    # Full CORS header enumeration
    extra_cors = {k: v for k, v in r.get("cors_headers", {}).items()
                  if k not in ("access-control-allow-origin", "access-control-allow-credentials")}
    for hname, hval in extra_cors.items():
        pretty = hname.title().replace("-", "-")
        print(f"            {pretty:<28}: {hval}")
    if r.get("body_leakage"):
        print(_c(f"            Body leakage: {', '.join(r['body_leakage'])}", RED + BOLD))
    if r.get("preflight_bypass"):
        pb = r["preflight_bypass"]
        print(_c(f"            Preflight   : {pb['message']}", RED + BOLD))
    print(f"            {r['message']}")
    print()


def print_header_bypass_results(findings: list[dict]) -> None:
    if not findings:
        print(_c("  [PASS    ]  Header injection bypass — no issues found\n", GREEN))
        return
    for f in findings:
        tag = _c("[HIGH    ]", YELLOW)
        hdr = list(f["injected_headers"].keys())[0]
        print(f"  {tag}  Header injection bypass ({hdr})")
        print(f"            Injected    : {f['injected_headers']}")
        print(f"            ACAO        : {f['acao_returned']}")
        print(f"            {f['message']}")
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
    timeout: int = 10,
    proxy: Optional[str] = None,
) -> int:
    """
    Run all probes against *url*.
    Returns exit code: 0 = clean, 1 = CRITICAL/HIGH found.
    """
    parsed = urllib.parse.urlparse(url)
    target_domain = parsed.hostname or ""
    target_scheme = parsed.scheme or "https"

    probes  = build_probes(target_domain, target_scheme)
    methods = ["GET"]
    if method.upper() != "GET":
        methods.append("OPTIONS")  # preflight check

    results = []

    if not json_output:
        print_banner(url)
        print(f"  Running {len(probes)} probes × {len(methods)} method(s)…\n")

    for probe in probes:
        for meth in methods:
            status, headers, body = send_request(
                url, meth, probe["origin"], cookies, timeout, proxy=proxy,
            )
            r = analyse(
                probe, probe["origin"], status, headers, body,
                url, cookies, timeout, proxy=proxy,
            )
            r["method"] = meth
            results.append(r)
            if not json_output:
                print_result(r)

    # ── Header injection bypass section ───────────────────────────────────────
    if not json_output:
        print(_c("  ── Header Injection Bypasses ──────────────────────────────", MAGENTA))
        print()
    header_bypass_findings = test_header_bypasses(url, cookies, timeout, proxy=proxy)
    if not json_output:
        print_header_bypass_results(header_bypass_findings)

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
            "findings":              [r for r in results if r["severity"] not in ("PASS",)],
            "header_bypass_findings": header_bypass_findings,
        }
        print(json.dumps(output, indent=2))
    else:
        divider = "─" * 50
        print(f"  {divider}")
        total_findings = len(criticals) + len(highs)
        if total_findings == 0 and not header_bypass_findings:
            print(_c("  No HIGH/CRITICAL findings. Target appears safe.", GREEN))
        else:
            if criticals:
                print(_c(f"  {len(criticals)} CRITICAL finding(s)!", RED + BOLD))
            if highs:
                print(_c(f"  {len(highs)} HIGH finding(s)!", YELLOW))
            if header_bypass_findings:
                print(_c(f"  {len(header_bypass_findings)} header-injection finding(s)!", YELLOW))
        print(f"  {divider}\n")

    return 1 if (criticals or highs or header_bypass_findings) else 0


# ── Bulk scanning ──────────────────────────────────────────────────────────────
def scan_list(
    path: str,
    method: str,
    cookies: Optional[str],
    json_output: bool,
    timeout: int,
    proxy: Optional[str],
) -> int:
    """
    Read URLs from *path* (one per line) and scan each.
    Prints per-URL summary and final statistics.
    Returns 1 if any URL has findings.
    """
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw_lines = fh.readlines()
    except OSError as exc:
        print(f"[ERROR] Cannot read list file: {exc}", file=sys.stderr)
        return 1

    urls = [line.strip() for line in raw_lines if line.strip() and not line.startswith("#")]
    if not urls:
        print("[ERROR] No URLs found in list file.", file=sys.stderr)
        return 1

    total      = len(urls)
    vulnerable = 0
    all_results: list[dict] = []

    if not json_output:
        print(_c(f"\n  Bulk scan: {total} URL(s)\n", CYAN))
        print("  " + "─" * 60)

    for idx, url in enumerate(urls, 1):
        parsed = urllib.parse.urlparse(url)
        if parsed.scheme not in ("http", "https"):
            if not json_output:
                print(f"  [{idx:3d}/{total}] SKIP  {url}  (invalid scheme)")
            continue

        if not json_output:
            print(f"  [{idx:3d}/{total}] Scanning {_c(url, BOLD)} …")

        # Redirect stdout temporarily if JSON so per-URL scan doesn't pollute output
        import io, contextlib
        buf = io.StringIO()
        ctx = contextlib.redirect_stdout(buf) if json_output else contextlib.nullcontext()
        with ctx:
            code = scan(
                url=url,
                method=method,
                cookies=cookies,
                json_output=False,   # collect text results internally
                timeout=timeout,
                proxy=proxy,
            )

        if code != 0:
            vulnerable += 1
            label = _c("VULN", RED + BOLD)
        else:
            label = _c("SAFE", GREEN)

        if not json_output:
            print(f"           → {label}\n")

        all_results.append({"url": url, "vulnerable": code != 0})

    if json_output:
        print(json.dumps({
            "bulk_scan": True,
            "total":      total,
            "vulnerable": vulnerable,
            "results":    all_results,
        }, indent=2))
    else:
        print("  " + "─" * 60)
        print(f"\n  Final stats: {_c(str(vulnerable), RED + BOLD if vulnerable else GREEN)}"
              f" / {total} URL(s) vulnerable\n")

    return 1 if vulnerable else 0


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
  python cors_scanner.py https://api.example.com/data --proxy http://127.0.0.1:8080
  python cors_scanner.py --list urls.txt --timeout 15
        """,
    )
    # Positional URL — optional when --list is used
    parser.add_argument(
        "url",
        nargs="?",
        default=None,
        help="Target URL to scan",
    )
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
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SECONDS",
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--proxy",
        metavar="URL",
        default=None,
        help="Proxy URL to route requests through, e.g. http://127.0.0.1:8080 (Burp Suite)",
    )
    parser.add_argument(
        "--list",
        metavar="FILE",
        dest="list_file",
        default=None,
        help="File containing one URL per line — scan each and print bulk summary",
    )

    args = parser.parse_args()

    # ── Bulk mode ──────────────────────────────────────────────────────────────
    if args.list_file:
        exit_code = scan_list(
            path=args.list_file,
            method=args.method,
            cookies=args.cookies,
            json_output=args.json_output,
            timeout=args.timeout,
            proxy=args.proxy,
        )
        sys.exit(exit_code)

    # ── Single-URL mode ────────────────────────────────────────────────────────
    if not args.url:
        parser.error("Provide a URL as positional argument, or use --list FILE")

    parsed = urllib.parse.urlparse(args.url)
    if parsed.scheme not in ("http", "https"):
        parser.error("URL must start with http:// or https://")

    exit_code = scan(
        url=args.url,
        method=args.method,
        cookies=args.cookies,
        json_output=args.json_output,
        timeout=args.timeout,
        proxy=args.proxy,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
