# Artais CORS Scout

A focused CLI tool that runs a tight set of high-signal CORS probes against one or many targets and outputs actionable findings with severity ratings and curl reproduction commands. Built for pentesters, bug bounty hunters, and appsec engineers who want fast, reliable CORS misconfiguration detection without the noise.

## Why Another CORS Scanner?

Most CORS tools blast dozens of origin permutations and dump raw headers, leaving you to triage the output. CORS Scout takes a different approach: a small, curated probe set designed to surface the misconfigurations that actually matter in a pentest report, with clear severity ratings and ready-to-paste curl commands for every finding.

## Install

```bash
git clone https://github.com/Artais-Security/artais-cors-scout.git
cd artais-cors-scout
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

Requires Python 3.10+. Dependencies: `httpx`, `rich`.

## Quick Start

Scan a single target:

```bash
cors-scout -u https://example.com
```

Scan specific API paths:

```bash
cors-scout -u example.com --paths /api,/graphql,/v2/users
```

Batch scan from a file:

```bash
cors-scout -i targets.txt --paths /api,/auth/token
```

Output JSON for CI/CD pipelines:

```bash
cors-scout -u example.com --json results.json
cors-scout -u example.com --json -    # JSON to stdout
```

## What Gets Tested

For each target URL, CORS Scout sends **10 probes** — a simple `GET` and an `OPTIONS` preflight for each of **5 origin values**:

| Origin | What It Catches |
|--------|----------------|
| `https://evil.example` | Arbitrary origin reflection — server echoes any Origin back in ACAO |
| `https://{target}.evil.example` | Subdomain/suffix matching bypass — server trusts origins containing the target hostname |
| `null` | Null origin acceptance — exploitable via sandboxed iframes and data URIs |
| `http://localhost:3000` | Developer/debug origin left in production allow-lists |
| `file://` | File origin acceptance — exploitable from local HTML files on victim machines |

Each origin is sent twice: once as a simple cross-origin `GET`, and once as an `OPTIONS` preflight requesting `PUT` with `Authorization`, `Content-Type`, and `X-Requested-With` headers. This catches servers that allow simple requests but also exposes permissive preflight configurations.

## Findings

CORS Scout evaluates responses and produces findings at four severity levels:

### HIGH

- **Credentialed Reflected Origin** — Server reflects the attacker-controlled `Origin` in `Access-Control-Allow-Origin` and sets `Access-Control-Allow-Credentials: true`. A malicious page can read authenticated responses from the victim's browser.
- **Wildcard ACAO with Credentials** — Server returns `Access-Control-Allow-Origin: *` alongside `Access-Control-Allow-Credentials: true`. Browsers should reject this combination, but it indicates broken CORS logic that may be exploitable via intermediaries.

### MEDIUM

- **Reflected Origin** — Server reflects the supplied `Origin` without credentials. Impact depends on whether sensitive data is returned, but the door is open.
- **Allows 'null' Origin (with credentials)** — Server accepts `Origin: null` and allows credentials. Sandboxed iframes and data URIs send a null origin, making this exploitable.
- **Dynamic ACAO without Vary: Origin** — Server reflects the `Origin` dynamically but omits `Vary: Origin`, creating a cache poisoning risk where a CDN or proxy could serve an attacker-origin response to legitimate users.

### LOW

- **Allows 'null' Origin** — Same as above but without credentials. Lower impact, but still worth noting.
- **Dynamic ACAO with missing Vary header** — `Vary` header is absent entirely. If any caching layer exists, this is a poisoning vector.

### INFO

- **Preflight allows PUT (or wildcard methods)** — Preflight response permits state-changing methods. Not a vulnerability on its own, but relevant context when paired with origin reflection.
- **Exposes response headers to JS** — `Access-Control-Expose-Headers` is set, increasing what attacker-controlled JavaScript could read if CORS is misconfigured.

Every finding includes the specific `Access-Control-*` header values observed, a description explaining the risk, and a **curl command** to reproduce the exact request.

## Usage Reference

```
cors-scout [-h] (-u URL | -i INPUT) [--paths PATHS] [--origin ORIGINS]
            [-c CONCURRENCY] [-t TIMEOUT] [-k] [--json JSON_OUT]
```

| Flag | Description |
|------|-------------|
| `-u`, `--url` | Single target URL or hostname (scheme defaults to `https://`) |
| `-i`, `--input` | File containing target URLs/hosts, one per line (`#` lines skipped) |
| `--paths` | Comma-separated paths to probe (default: `/`) |
| `--origin` | Override the default origin set. Repeatable: `--origin https://evil.com --origin null` |
| `-c`, `--concurrency` | Max concurrent requests (default: `50`) |
| `-t`, `--timeout` | Per-request timeout in seconds (default: `10`) |
| `-k`, `--insecure` | Disable TLS certificate verification |
| `--json` | Write JSON report to a file path, or `-` for stdout |

## Examples

### Pentest Workflow

Test an API with custom paths and output JSON alongside the console report:

```bash
cors-scout -u api.target.com \
  --paths /v1/users,/v1/accounts,/graphql \
  --json cors-findings.json
```

### Bug Bounty Batch Scan

Feed a list of subdomains from recon and scan them concurrently:

```bash
# targets.txt:
# api.example.com
# app.example.com
# staging.example.com

cors-scout -i targets.txt --paths /,/api -c 100
```

### Custom Origins

Override the default origin set to test specific scenarios:

```bash
cors-scout -u example.com \
  --origin "https://attacker.com" \
  --origin "https://example.com.attacker.com" \
  --origin "null"
```

### Internal Targets with Self-Signed Certs

```bash
cors-scout -u https://internal-app.corp:8443 -k
```

### CI/CD Gate

Fail a pipeline if any HIGH-severity findings are detected:

```bash
cors-scout -u https://api.yourapp.com --paths /api --json - \
  | jq -e '[.findings[] | select(.severity == "high")] | length == 0'
```

## JSON Output Schema

```json
{
  "findings": [
    {
      "severity": "high",
      "title": "Credentialed Reflected Origin",
      "url": "https://example.com/api",
      "origin": "https://evil.example",
      "evidence": {
        "access-control-allow-origin": "https://evil.example",
        "access-control-allow-credentials": "true"
      },
      "description": "Server reflects the supplied Origin and allows credentials...",
      "repro_curl": "curl -i -s \"https://example.com/api\" -H \"Origin: https://evil.example\""
    }
  ]
}
```

## Project Structure

```
cors_scout/
├── cli.py       # Argument parsing, target loading, async scan orchestration
├── probes.py    # Probe definitions, origin generation, HTTP request execution
├── checks.py    # Response analysis, finding generation, severity classification
├── report.py    # JSON serialization and Rich console output
└── util.py      # URL normalization and string helpers
tests/
└── test_checks.py
```

## Contributing

Pull requests welcome. Please include tests for new checks or probes.

```bash
python -m pytest tests/ -v
```

## License

MIT — see [LICENSE](LICENSE).

---

Built by [Artais Security](https://artais.io) — offensive security consulting and penetration testing.
