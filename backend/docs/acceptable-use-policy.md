# Acceptable Use Policy

## Overview

Cartographer is a passive OSINT (Open Source Intelligence) tool. By using it,
you agree to the following terms. This policy is enforced in code, not just
in documentation.

## Core Rules

### 1. Passive Collection Only

Every collector hits public APIs or public records only:

- **crt.sh** — Public Certificate Transparency logs (no API key needed).
- **GitHub Search API** — Public code search via authenticated API.
- **Shodan** — Uses Shodan's indexed data API (not active port scanning).
- **VirusTotal** — Uses VT's domain/report API (not file uploads or active scans).
- **HaveIBeenPwned** — Uses HIBP's breach-lookup API (breach data is already public).
- **Cloudflare DoH** — DNS-over-HTTPS resolution (passive DNS query, no scanning).

There is NO active scanning, credential testing, login attempts, or
unauthorized access anywhere in this codebase.

### 2. Authorization Gate

Every investigation request requires `authorized: true`. If this field is
`false`, the request is rejected with HTTP 400 before any collector runs.
This creates an audit trail and mirrors how real pentest/OSINT tools operate.

### 3. Authorization Confirmation

You must confirm that you are:
- The owner of the target, OR
- Authorized in writing by the target owner to conduct OSINT investigation.

### 4. Rate Limiting as a Safeguard

Rate limiters are enforced in code (Redis-backed token buckets) and match
each source's documented API limits. This protects both the source APIs
(from abusive traffic) and your API keys (from being revoked mid-investigation).

### 5. Data Minimization

- Raw findings are cached in Redis with per-source TTLs (5 minutes to 48 hours).
- Investigation results expire after 24 hours by default.
- No raw findings are persisted to disk; PDFs are generated on-demand and streamed.

### 6. Source ToS Compliance

- **LinkedIn**: Not integrated. Use LinkedIn's official API/partner program instead.
- **Dark web / onion marketplaces**: Not integrated. Scraping these creates legal
  exposure. We use legitimate breach aggregators (HIBP) and threat-intel APIs
  (VirusTotal) instead.
- All other sources respect each API's rate limits and ToS.

### 7. No Dark-Web Scraping

This tool does not scrape onion marketplaces, paste sites, forums, or any
service that traffics in stolen credentials.

## Violation Consequences

Violations result in:
- Immediate revocation of API access
- Permanent blocking from source APIs
- Legal action if unauthorized access is detected

## Ethical Use

Use this tool to:
- Protect your own digital assets
- Support legitimate security research (with authorization)
- Educate others on OSINT best practices

Do not use this tool to:
- Harass individuals
- Investigate targets you do not own or lack authorization for
- Attempt active exploitation or scanning
