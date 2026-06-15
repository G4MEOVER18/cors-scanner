# cors-scanner

**CORS-Fehlkonfigurationsscanner in Python 3 — ohne externe Abhängigkeiten.**  
Erkennt reflektierte Origins, Null-Origin-Bypass, Subdomain/Suffix/No-Separator-Regex-Bypasses und Credential-Leakage — ausschließlich mit der Python-Standardbibliothek.

---

## Was sind CORS-Fehlkonfigurationen?

Cross-Origin Resource Sharing (CORS) ermöglicht es Servern festzulegen, welche externen Origins ihre Antworten lesen dürfen. Eine falsch konfigurierte CORS-Policy kann es einer vom Angreifer kontrollierten Seite erlauben, **authentifizierte Requests** an eine API im Namen eines eingeloggten Opfers zu stellen und die Antwort auszulesen — die Same-Origin Policy wird damit faktisch ausgehebelt.

**Warum das relevant ist:**
- Ein Angreifer betreibt eine Seite auf `evil.com`
- Das Opfer besucht `evil.com`, während es bei `api.bank.com` eingeloggt ist
- Wenn `api.bank.com` `evil.com` im `Access-Control-Allow-Origin`-Header zurückspiegelt **und** gleichzeitig `Access-Control-Allow-Credentials: true` sendet, kann das JavaScript des Angreifers die authentifizierte API-Antwort auslesen
- Mögliche Folgen: Account Takeover, Datenexfiltration, CSRF-Amplifikation

---

## Probe-Übersicht

| # | Probe | Gesendete Origin | Risiko bei Reflection |
|---|-------|------------------|----------------------|
| 1 | Arbitrary Origin Reflection | `https://evil.com` | HIGH / CRITICAL |
| 2 | Null Origin Reflection | `null` | HIGH / CRITICAL — Sandbox-iFrame-Bypass |
| 3 | Subdomain Prefix Bypass | `https://<target>.evil.com` | HIGH / CRITICAL — schwache `endsWith`-Regex |
| 4 | TLD Suffix Bypass | `https://evil.com.<target>` | HIGH / CRITICAL — schwache `startsWith`-Regex |
| 5 | No-Separator Bypass | `https://<target>evil.com` | HIGH / CRITICAL — fehlendes `$`-Anker in Regex |

**Schweregradklassifizierung:**

| Schweregrad | Bedingung |
|-------------|-----------|
| `CRITICAL` | Origin wird reflektiert **und** `Access-Control-Allow-Credentials: true` |
| `HIGH` | Origin wird reflektiert, kein Credentials-Header |
| `INFO` | Wildcard `ACAO: *` (nicht-authentifizierte Ressourcen exponiert) |
| `PASS` | Origin wird nicht reflektiert |

---

## Installation

Keine Abhängigkeiten. Benötigt **Python 3.10+**.

```bash
git clone https://github.com/G4MEOVER18/cors-scanner.git
cd cors-scanner
python cors_scanner.py --help
```

---

## Verwendung

```
usage: cors_scanner [-h] [--json] [--cookies COOKIE_STRING] [--method METHOD] url

positional arguments:
  url                   Ziel-URL für den Scan

options:
  -h, --help            Hilfe anzeigen
  --json                Ergebnisse als JSON ausgeben (maschinenlesbar)
  --cookies COOKIE_STRING
                        Session-Cookie-String, z. B. "session=abc123; csrf=xyz"
  --method METHOD       HTTP-Methode für den Hauptrequest (Standard: GET).
                        POST/PUT/DELETE löst zusätzlich eine OPTIONS-Preflight-Probe aus.
```

### Beispiele

```bash
# Einfacher Scan
python cors_scanner.py https://api.example.com/v1/user

# Authentifizierter Scan (Session-Cookie mitgeben)
python cors_scanner.py https://api.example.com/v1/user \
    --cookies "session=abc123def456; csrf=xyz789"

# Maschinenlesbare JSON-Ausgabe (z. B. für CI-Pipelines)
python cors_scanner.py https://api.example.com/v1/user --json

# POST-Endpoint + OPTIONS-Preflight testen
python cors_scanner.py https://api.example.com/v1/data --method POST

# In CI einbinden: Exit-Code 1 bei CRITICAL/HIGH
python cors_scanner.py https://api.example.com/v1/user || echo "CORS issue found!"
```

---

## Beispielausgabe

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

### JSON-Ausgabe (`--json`)

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

## Rechtlicher Hinweis

Dieses Tool ist ausschließlich für **autorisierte Sicherheitstests** gedacht. Nur Systeme scannen, die dir gehören oder für die du eine ausdrückliche schriftliche Genehmigung besitzt. Unautorisiertes Scannen kann in deiner Jurisdiktion gegen Gesetze zur Computerkriminalität verstoßen.

---

## Mitmachen

Issues und Pull Requests sind willkommen. Bitte die Zero-Dependency-Anforderung einhalten — ausschließlich stdlib.

---

## Spenden

Wenn das Tool dir Zeit gespart hat, freue ich mich über eine kleine Unterstützung:

**Bitcoin:** `39vZWmnUwDReQ15BwqQXzyqVQ6U8LardEf`

**Kontakt:** [g4me.over.18@gmail.com](mailto:g4me.over.18@gmail.com)
**PayPal:** [paypal.me/Freakbank1](https://paypal.me/Freakbank1)

---

## Lizenz

MIT License — Copyright (c) 2026 Yanis Ameseder. Siehe [LICENSE](LICENSE).
