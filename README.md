# 🔍 SecurAI Active Scanner

[![Security Scan](https://github.com/ElhamBidarigh/securAI-active-scanner/actions/workflows/security-scan.yml/badge.svg)](https://github.com/ElhamBidarigh/securAI-active-scanner/actions/workflows/security-scan.yml)

A PHP-based tool that fetches a live URL and runs 11 non-destructive security checks — then produces a visual report with a risk score.

**WARNING: Only scan sites you own or have written permission to test. Unauthorized scanning is illegal in many jurisdictions.**

## What it checks

| # | Check | Severity |
|---|-------|----------|
| 1 | HTTP to HTTPS redirect | High |
| 2 | Security headers (HSTS, CSP, X-Frame-Options) | Medium-High |
| 3 | Server / X-Powered-By disclosure | Low |
| 4 | Cookie flags (Secure, HttpOnly, SameSite) | Medium |
| 5 | CORS misconfiguration | Critical |
| 6 | Exposed files (.git/HEAD, .env, .htaccess) | Critical-High |
| 7 | robots.txt disclosure | Low |
| 8 | Directory listing | Medium |
| 9 | Dangerous HTTP methods (TRACE, PUT, DELETE) | Medium-High |
| 10 | Open redirect parameters | High |
| 11 | Weak HSTS max-age | Medium |

All checks are non-destructive — no exploitation, no fuzzing, no payloads that could damage the target.

## Quick start

Run these commands in your terminal:

    git clone https://github.com/ElhamBidarigh/securAI-active-scanner.git
    cd securAI-active-scanner
    docker compose up -d

Then open http://localhost:8090 in your browser.

Enter a URL (e.g. https://example.com) and click Scan.

## Example output

The scanner produces:

- Risk score (0-100) with a circular gauge
- Counts by severity (Critical / High / Medium / Low)
- Per-finding cards with title, description, and the exact fix
- All rendered in a clean dark-mode UI

## Requirements

- PHP 8.0+ with the curl extension
- Docker (for the included docker-compose.yml)

## Rate limiting

By default, the scanner allows 10 scans per hour per session.

## SSRF protection

The scanner refuses to scan:

- localhost, 127.0.0.1
- Private ranges (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12)
- Link-local (169.254.0.0/16)
- IPv6 loopback (::1)

This prevents the tool from being abused as an SSRF proxy.

## The full SecurAI toolkit

| Tool | Type | Link |
|------|------|------|
| 🛡️ Audit Tool | Self-assessment (browser) | [Live demo](https://elhambidarigh.github.io/securai/) |
| 🔬 Vuln Lab | Educational (PHP/MySQL) | [Repo](https://github.com/ElhamBidarigh/securAI-vuln-lab) |
| ⚙️ Security Action | CI/CD (GitHub Actions) | [Workflow](https://github.com/ElhamBidarigh/securAI-vuln-lab/tree/main/.github/workflows) |
| 🔍 Active Scanner | Live URL scanner (PHP) | You are here |

## Use cases

- Before launching a new site — catch missing headers and exposed files
- Before a security review — generate a quick snapshot of the attack surface
- For client work — produce a shareable HTML report
- For learning — see how common misconfigurations look in HTTP responses

## License

MIT — use responsibly.
