# Scanners and Threat Intelligence

This document describes how Horus discovers assets, scans them for vulnerabilities, and enriches findings with threat intelligence. It covers the three scanning engines, every external intelligence source, and the post-scan logic that turns raw findings into prioritized, noise-free work items.

---

## 1. Scanner overview

Horus uses three complementary scanning engines. Each answers a different question and covers a different attack surface.

| Engine | What it tests | When it runs |
|--------|--------------|-------------|
| **Nmap** | Open ports, service versions, NSE vulnerability scripts | Every scan; port-focused and network-layer |
| **Nuclei** | Template-based checks (CVEs, misconfigs, exposed panels) | Every scan alongside Nmap; application-layer |
| **ZAP** | DAST web scanning (spider + active scan) | On-demand for HTTP targets; requires ZAP daemon |

All three produce `RawFinding` objects that flow into the same pipeline, where they are enriched with CVE data, deduplicated, and SSVC-prioritized.

---

## 2. Nmap scanner

**Source:** `backend/scanners/nmap_scanner.py`

### What it scans

By default Nmap targets a curated list of ports that commonly expose vulnerabilities:

```
21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995,
3306, 3389, 5432, 6379, 8080, 8443, 27017
```

You can override this by passing a single port number (e.g. when scanning a specific known service). The scan uses:

- `-sV`: service and version detection. This is the primary output the pipeline uses for CPE-to-CVE correlation.
- `--script vuln,default`: runs the standard NSE vulnerability and discovery scripts.
- `--script-timeout 30s`: prevents hung network-dependent scripts (such as `vulners`) from stalling the scan indefinitely.
- `--host-timeout 3m`: hard wall-clock limit per host.

The overall process timeout is 240 seconds. On timeout the child process group is killed cleanly before the method returns an empty result.

### Informational script filtering

A large set of NSE scripts report contextual information (page titles, TLS certificate fields, server banners, HTTP headers) rather than vulnerabilities. Horus drops these at parse time so the Findings view is not polluted:

```
http-title, http-server-header, http-headers, http-methods, http-favicon,
http-robots.txt, http-generator, http-date, http-comments-displayer,
ssl-cert, ssl-date, tls-alpn, tls-nextprotoneg, banner, fingerprint-strings,
ssh-hostkey, ssh-auth-methods, http-auth-finder, dns-service-discovery,
broadcast-dns-service-discovery, http-open-proxy, http-trace,
rdp-enum-encryption, smb-security-mode, smbv2-enabled
```

Service and version data from these scripts still flows through via `-sV` detected services, which is what drives CPE-to-CVE correlation downstream.

### Low-confidence scripts

Certain XSS and client-side injection scripts report potential issues rather than confirmed ones. Horus keeps these as findings but marks them with `confidence: 0.4` and `needs_verification: true`, signalling the validation agent to treat them with appropriate skepticism:

```
http-csrf, http-phpself-xss, http-stored-xss, http-reflected-xss,
http-xssed, http-unsafe-output-escaping
```

### Severity inference

Script output text is inspected for severity signals when the NSE script does not provide a structured CVSS score:

| Keywords in output | Assigned severity |
|--------------------|------------------|
| `exploit`, `rce`, `critical`, `cvss: 9/10` | critical |
| `vulnerable`, `high`, `cvss: 7/8` | high |
| `medium`, `cvss: 4/5/6` | medium |
| (anything else) | low |

### Detected services for CPE correlation

For every open port where Nmap detects a product name and version (or at minimum a service name and version), the scanner records a service entry:

```python
{"product": "nginx", "version": "1.18.0", "port": "443",
 "service": "http", "extrainfo": ""}
```

These entries flow to `cpe_intel.correlate_services()` to look up applicable CVEs.

---

## 3. Nuclei scanner

**Source:** `backend/scanners/nuclei_scanner.py`

### How it works

Nuclei runs against a target using its built-in community template library. The invocation:

```
nuclei -target <host[:port]> -jsonl-export <out> -severity critical,high,medium,low
       -silent -no-interactsh -disable-update-check
```

Key flags:
- `-jsonl-export`: writes one JSON object per line (JSONL). The parser tolerates both JSONL and a single JSON array, so both output shapes work.
- `-no-interactsh`: disables out-of-band interaction testing, which would require an external callback server and adds scan time.
- `-disable-update-check`: skips the template auto-update on every run. Templates are managed outside the scan loop to avoid latency and potential mid-scan template state changes.
- `-severity critical,high,medium,low`: info-severity templates (version disclosures, header checks) are excluded to reduce noise.

The process timeout is 300 seconds.

### Severity mapping

Nuclei templates carry their own `info.severity` field. This value is passed directly into `RawFinding.severity`, so the Nuclei template author's classification is preserved. Valid values are `critical`, `high`, `medium`, `low`, and `info`.

### Output

Each matched template produces a finding with:

- `tool`: `"nuclei"`
- `template_id`: the Nuclei template ID (e.g. `CVE-2021-44228`)
- `name`: the human-readable template title from `info.name`
- `host`: the scanned target
- `severity`: from `info.severity`
- `raw`: the full Nuclei JSON record (includes matched URL, extracted data, request/response evidence)

---

## 4. ZAP scanner (DAST)

**Source:** `backend/scanners/zap_scanner.py`

### What it does

OWASP ZAP provides a full Dynamic Application Security Testing (DAST) scan: it spiders the target to discover pages and endpoints, then runs an active scan against everything it found. This covers application-layer issues that a port scanner cannot see: SQL injection, XSS, insecure cookies, missing security headers, CORS misconfigurations, and similar web-specific problems.

### Requirements

ZAP must be running as a daemon before any scan is triggered:

```bash
zap.sh -daemon -port 8090
```

An optional `ZAP_API_KEY` environment variable can be set when the ZAP instance is configured to require authentication. If ZAP is not reachable, the scanner logs a warning and returns an empty result rather than failing the entire scan job.

### Scan flow

1. **Spider:** `GET /JSON/spider/action/scan/` on the target URL. This crawls all reachable pages and forms.
2. **Active scan:** `GET /JSON/ascan/action/scan/` launches the vulnerability probe. ZAP returns a `scan_id`.
3. **Polling:** The scanner polls `ascan/view/status` every 2 seconds until the scan reports 100% completion or the 300-second timeout is reached.
4. **Alerts:** `GET /JSON/alert/view/alerts/` retrieves all findings for the target URL.

### Severity mapping

ZAP uses its own risk labels, which are mapped to Horus severity levels:

| ZAP risk | Horus severity |
|----------|---------------|
| High | high |
| Medium | medium |
| Low | low |
| Informational | info |

### When ZAP is used

ZAP is suited to HTTP/HTTPS targets where you want comprehensive web application coverage beyond what NSE scripts provide. It is most valuable for internet-facing web applications and APIs. Because it requires a running daemon and can take minutes per target, it is typically invoked on-demand rather than as part of every background scan.

---

## 5. Threat intelligence sources

After scanning, Horus enriches findings and assets with data from multiple external intelligence sources. These integrations run deterministically against structured data rather than asking an LLM to recall CVE information.

### 5.1 CVE and CVSS/EPSS from NVD and CISA

**Source:** `backend/core/cve_intel.py`

Three feeds are merged into the `cve_intel` table, keyed by CVE ID.

**CISA KEV (Known Exploited Vulnerabilities):** The authoritative "act now" signal. The catalog is small (around 1,200 CVEs) but curated: every entry represents a vulnerability known to be exploited in the wild. Fields captured include the date added, whether ransomware campaigns are known to use it, and a short description.

**FIRST EPSS (Exploit Prediction Scoring System):** A probabilistic score (0 to 1) representing the likelihood that a CVE will be exploited in the next 30 days. The feed covers around 250,000 CVEs. The previous day's EPSS scores are snapshotted before each sync via a database procedure so that Watchtower can detect day-over-day spikes.

**NVD CVSS:** CVSS base scores and severity labels are fetched from the NVD 2.0 API for KEV CVEs that are missing scores in the database. The fetcher handles rate limits automatically:
- Without an NVD API key: 4 requests per 30-second window (NVD allows 5; one request of margin).
- With an NVD API key: 40 requests per 30-second window (NVD allows 50; ten requests of margin).

HTTP 429 responses trigger a single retry after waiting a full window boundary. Score preference order is CVSS v3.1, then v3.0, then v2. For v2 scores that omit a severity label, the label is derived from the numeric score.

The `lookup_cves(cve_ids)` function provides a deterministic, database-backed lookup for the scan pipeline, replacing any LLM-based recall of threat data.

### 5.2 CPE matching against NVD

**Source:** `backend/core/cpe_intel.py`

When Nmap detects a product name and version on an open port, the pipeline asks NVD which CVEs apply to that specific product+version combination using the CPE 2.3 match string format:

```
cpe:2.3:a:<vendor>:<product>:<version>:*:*:*:*:*:*:*
```

NVD performs the version-range matching server-side, which is authoritative and maintained.

**Product alias resolution:** Scanner product labels and NVD CPE names often differ. A curated alias table maps common scanner names to their correct CPE vendor and product tokens:

```python
"apache_httpd"  -> ("apache", "http_server")
"openssh"       -> ("openbsd", "openssh")
"nginx"         -> ("*", "nginx")
"mysql"         -> ("oracle", "mysql")
# ... and many others
```

When no alias exists, the normalized scanner label is used with a wildcard vendor.

**Service name fallbacks:** When Nmap reports a service type but no product name (for example `service="ftp"` with a version), the lookup falls back to a default product for that service type (`vsftpd` for FTP, `dovecot` for IMAP/POP3, and so on).

**Version normalization:** Scanner version strings often include distribution packaging suffixes (for example `8.2p1 Ubuntu 4ubuntu0.13`). Only the leading version token is extracted before the NVD query, since NVD CPE requires a clean version field.

**Caching:** Results are cached in `cpe_lookup_cache` keyed by `vendor:product:version`. Cache entries are considered fresh for a configurable number of days (default 7). On NVD failure, any stale cache entry is returned as a fallback rather than returning nothing.

CVSS scores retrieved during CPE lookups are folded into the `cve_intel` table so all severity, KEV, and EPSS data lives in one place.

### 5.3 HaveIBeenPwned breach data

**Source:** `backend/core/hibp.py`

Horus queries the HIBP v3 Domain Search API daily for each organization's email domain to find employees whose accounts appeared in known data breaches. The check runs across all registered employees and does the following for each affected account:

1. **Breach record:** Stored in `credential_breaches` with the breach name, date, and data classes exposed (passwords, auth tokens, email addresses, and so on).
2. **Asset correlation:** The breach is linked to all active assets in the organization, representing the set of systems the employee could potentially access with compromised credentials.
3. **Karma score:** Each breach deducts 10 points from the employee's karma score (floor 0, maximum 100). Breaches exposing passwords or auth tokens deduct 20 points. This score surfaces credential hygiene risk in the People view.

The check also updates `hibp_checked_at` on each employee record, even for clean accounts, so the UI can show when the last check ran.

The Domain Search endpoint is rate-limited to one request per domain per day in practice. Horus runs this check via the daily scheduler rather than in-process.

### 5.4 IntelligenceX dark web search

**Source:** `backend/core/intelx.py`

IntelligenceX provides search across dark web sources: Tor, I2P, Pastebin, leak databases, and paste sites. Horus uses a two-step flow:

1. **Initiate:** POST to `/intelligent/search` with the search term (domain, IP, or email). The API returns a `search_id`.
2. **Poll:** GET `/intelligent/search/result?id=<search_id>` up to 3 times at 2-second intervals, or until the API returns status 2 (complete). The entire search is bounded by a 30-second hard timeout.

Each result record is normalized to `{name, date, bucket, source: "intelx"}`. The `is_darkweb_result()` helper checks whether a bucket falls into a dark web category (`darkweb`, `leaks`, `pastes`, `i2p`, `tor`, `onion`).

The free tier of IntelligenceX provides approximately 10 searches per month. API key required; a missing key raises `ValueError` immediately.

### 5.5 Abuse.ch threat feeds (ThreatFox and URLhaus)

**Source:** `backend/core/abuse_intel.py`

Two public threat feeds from abuse.ch are queried without authentication.

**ThreatFox:** A searchable IOC database covering command-and-control (C2) servers, malware distribution infrastructure, and botnet endpoints. A POST to the ThreatFox API with an IP or domain returns all matching IOC records, including threat type, malware family, confidence level (0-100), first/last seen dates, and any associated tags. A `query_status` of `"ok"` indicates results were found; `"no_result"` means the indicator is clean.

**URLhaus:** A database of malicious URLs and the hosts serving them. A POST to the URLhaus host endpoint returns all malicious URLs associated with a domain or IP, along with URL status (online/offline/unknown), threat category, and a direct URLhaus reference link.

Both integrations use 10-second timeouts and return empty results on any network or HTTP error, so a temporary abuse.ch outage does not block a scan.

### 5.6 Breach Directory credential exposure

**Source:** `backend/core/breach_directory.py`

BreachDirectory (hosted on RapidAPI) allows querying specific email addresses or entire domains against its breach database. Unlike HIBP, BreachDirectory returns the SHA1 hash of the compromised credential, which can be used to confirm the specific account password was exposed.

The client supports two query modes:

- `check_email(email, api_key)`: checks a single email address.
- `check_domain(domain, api_key)`: returns all breached accounts under a domain.

Both return a normalized result:
```python
{
    "found": bool,
    "sources": [{"name": str, "date": str|None, "count": int}],
    "sha1_hash": str|None,
}
```

The free tier allows 50 requests per day. Rate limit exhaustion (HTTP 429) raises a `ValueError` with a message that surfaces in the UI. API key required.

### 5.7 Ransomware group tracking

**Source:** `backend/core/ransomware_intel.py`

Horus queries the Ransomware.live public API for recent ransomware victim disclosures. The `check_domain(domain)` function:

1. Fetches recent victims from `/recentvictims` (falling back to `/victims` if unavailable).
2. Extracts the root domain from each victim's website field, post title, group name, and victim name.
3. Returns all entries where the query domain matches any of those fields.

Domain normalization strips `www.` prefixes, ports, and subdomains so that `www.example.com:8080` and `mail.internal.example.com` both match against `example.com`.

Matched victims are normalized to a stable structure:
```python
{
    "title", "group", "victim", "discovered_at",
    "leak_url", "description", "website", "country",
    "source": "ransomware.live",
}
```

No authentication is required. The integration uses a 15-second timeout and returns an empty list on failure.

---

## 6. SSVC prioritization

**Source:** `backend/core/ssvc.py`

Horus uses CISA's Stakeholder-Specific Vulnerability Categorization (SSVC) deployer decision tree to assign an action priority to each finding. SSVC answers "what should we do about this, given how exploited it is and how exposed we are?" rather than just "how bad is this vulnerability in the abstract?".

### Decision points

Each finding is evaluated against four inputs:

| Decision point | Values | Derivation |
|---------------|--------|-----------|
| **Exploitation** | `none`, `poc`, `active` | From KEV status and EPSS score |
| **Exposure** | `small`, `controlled`, `open` | From asset `is_internal` flag |
| **Automatable** | `yes`, `no` | Heuristic: active/public exploit on high/critical severity |
| **Technical impact** | `partial`, `total` | From severity label and CVSS score |

### Mappers

**`exploitation_from(exploitability, public_exploits_exist)`:** Maps the pipeline's exploitability signal to an SSVC exploitation value. KEV membership maps to `active`; high or medium EPSS or a known public exploit maps to `poc`; otherwise `none`.

**`exposure_from(is_internal)`:** Internet-facing assets are `open`; internal assets are `controlled`. The `small` value is not currently assigned (no supporting signal exists), so internal assets are never under-rated.

**`technical_impact_from(severity, cvss_score)`:** CVSS score >= 9.0 or a `critical` severity label maps to `total`; everything else is `partial`.

**`automatable_from(exploitation, severity, public_exploits_exist)`:** `True` only when the vulnerability has a real weaponization signal (active exploitation or a public exploit) and the severity is `critical` or `high`. This is conservative by design: SSVC defaults Automatable to `no` under uncertainty.

### Outcomes

The decision tree produces one of four priority labels:

| Priority | Default remediation mode | Meaning |
|----------|------------------------|---------|
| **Act** | approval_required | Address immediately |
| **Attend** | approval_required | Schedule within sprint |
| **Track\*** | suggest_only | Monitor; act if context changes |
| **Track** | suggest_only | Low urgency; record and review periodically |

Active in-the-wild exploitation is the dominant signal: an actively exploited vulnerability on an internet-facing asset always reaches at least `Attend`, and reaches `Act` when the exploit is automatable or the impact is total. Conservative ties resolve downward: when a signal is absent, the lower-urgency branch is chosen to avoid over-escalating on a guess.

The `decide()` function is a pure function with no side effects and is independently unit-tested.

---

## 7. Noise filtering

**Source:** `backend/core/noise.py`

Nmap NSE scripts and some LLM Analyst outputs produce "absence-of-vulnerability" output: "Not vulnerable to CVE-...", "No DOM-based XSS found on port 8080", "Script execution failed". These entries are not findings; persisting them as such drowns real signal in the Findings list.

Horus applies a two-tier deterministic classifier at persist time.

### Tier 1: Severity-independent absence patterns

These patterns match regardless of severity. They identify text that explicitly states nothing was found:

- `not vulnerable`
- `returned/reported/revealed no finding/vulnerability/issue/result`
- `couldn't/could not/unable to find/detect/identify`
- `none found/detected/identified`

### Tier 2: Info-severity noise patterns

These patterns only suppress findings when the severity is `info`. At `medium` or above, similar phrasing often represents a real missing control ("No rate limiting found on login endpoint") that should remain visible.

- Leading `No ... found/detected/identified/observed`
- `script error`, `script execution failed`
- `inconclusive`
- `(negative)`

Any finding flagged as noise is stored with `is_noise: true` and hidden from the default Findings list. It can still be retrieved by explicitly requesting noise records, preserving the full audit trail.

The patterns in this module are kept in sync with a database backfill migration (`supabase/migrations/20260610100000_findings_noise.sql`) that retroactively classifies historical findings.

---

## 8. Active service probing

**Source:** `backend/core/active_probe.py`

The most common source of false positives in Horus is version-only CVE correlations: Nmap detected `nginx 1.18.0` during a previous scan, the pipeline found matching CVEs, but the package may have been patched without a version bump or the service may no longer be running. The SSVC debate agents could guess; the active probe checks.

This module makes a single, non-destructive connection to the live service and asks: is that exact version string still present in the response?

### Probe strategy

- **HTTP/HTTPS ports** (80, 8080, 8000, 8888, 443, 8443): an HTTP GET to `/` with `User-Agent: Horus-ActiveValidation/1.0`. The `Server` response header and HTTP status code are read as the banner.
- **Other ports:** a raw TCP connection. SSH, FTP, and SMTP send greeting banners unprompted; up to 256 bytes are read.

### Outcome classification

| Condition | Outcome | Verdict |
|-----------|---------|---------|
| Port unreachable | `absent` | `false_positive` — service gone or host changed |
| Connected; version string in banner (and product token matches when known) | `confirmed_version` | `confirmed` — vulnerable version is live |
| Connected; version string not in banner | `service_present` | `None` — inconclusive, defer to debate |

A confirmed match requires both the version string and, when a product name is known, a product token in the banner. This prevents a bare version number in an unrelated response header from generating a false confirmation.

### Configuration and injection

Active probing is off by default (`active_validation_enabled` setting) because it makes a live network connection. It is opt-in.

The transport layer (`fetcher`) is dependency-injected, allowing unit tests to supply a mock without opening any sockets. The decision logic (`assess_probe`, `probe_to_verdict`) is pure and tested independently of the transport.

---

## 9. Asset discovery

**Source:** `backend/core/discovery.py`

Discovery maps an organization's attack surface before scanning begins. Two modes are supported.

### 9.1 Domain-based discovery (passive)

Given a domain (for example `example.com`), the pipeline enumerates subdomains from public sources without sending any traffic to the target organization.

**Step 1: Certificate Transparency logs.** `crt.sh` is queried for all certificates issued to `*.example.com`. Each certificate's `name_value` field may contain multiple hostnames (wildcard entries, SANs). The parser strips `*.` prefixes, normalizes case, and filters out names that don't belong to the target domain. `crt.sh` is retried up to a configurable number of times because it is occasionally slow or flaky. On persistent failure, the pipeline falls back to Certspotter as an alternative CT log source.

**Step 2: DNS brute-force.** A curated list of approximately 80 common subdomain labels (`www`, `mail`, `api`, `admin`, `staging`, `git`, `jenkins`, `grafana`, and many others) is resolved concurrently against the domain. Only labels that return at least one A or AAAA record are kept. This finds hosts that were never issued a TLS certificate (internal tools, HTTP-only services, redirectors) and therefore do not appear in CT logs.

**Step 3: DNS resolution and validation.** Each discovered name is resolved to confirm it is live. Names that resolve to private, reserved, or cloud metadata IP ranges are rejected by the same `target_validation` guard used by the scanners. This ensures internal infrastructure discovered via public CT logs is never silently added to the asset inventory.

**Step 4: Asset creation.** New hosts (not already in the org's inventory) are created as assets with `type: "domain"`, `is_internal: false`, and the `discovered` tag. A configurable per-run cap prevents a single discovery run from flooding the inventory.

### 9.2 Network-based discovery (active)

For internal networks, a CIDR block can be registered as a discovery source (for example `10.0.0.0/24`). The pipeline runs an `nmap -sn` ping sweep:

```bash
nmap -sn -T4 --max-retries 1 -oX - <cidr>
```

The XML output is parsed to extract the IP address and hostname of every host with `status=up`. Discovered hosts are created as assets with `type: "ip"`, `is_internal: true`, and the `internal` + `discovered` tags.

**Safety guard:** The CIDR is validated before nmap is invoked. Public (non-private) ranges and ranges larger than a configurable maximum (to prevent accidental `/8` sweeps) are rejected with a `ValueError`. This check runs before any shell command is issued.

Both discovery modes update the `last_run_at` and `last_found_count` fields on the discovery source record, and emit an audit log entry with a summary of names found and assets created.
