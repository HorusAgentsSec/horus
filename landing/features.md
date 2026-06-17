# Horus — Feature Reference

Generated from codebase analysis 2026-06-16.

## Vision

**Configure once. AI agents secure your infrastructure 24/7.**

Horus deploys eight specialized AI agents (Recon, Analyst, Threat Intel, Validation, Red Team, Blue Team, Risk Manager, Reporter) that run continuously on a schedule you define. The deterministic core (CVE correlation, SSVC prioritization, Watchtower, posture scoring) never calls an LLM — zero tokens, zero cost, zero hallucinations. LLM agents are optional, isolated, and data-redacted before any cloud call.

---

## Modules

### 1. Asset Discovery
- Certificate Transparency log sweep (crt.sh + certspotter fallback) → live subdomains
- nmap CIDR ping sweep → internal IPs
- Auto-deduplication of discovered assets
- Optional auto-create: discovered assets become scan targets automatically
- Configurable schedule: manual, daily, weekly, monthly

### 2. Asset Inventory
- CRUD for domains, IPs, APIs, services
- Tags for logical grouping (production, internal, third-party)
- Internal vs external classification
- Scan history + last-detected technologies per asset

### 3. Vulnerability Scanning
- Port enumeration + service detection (nmap)
- Known vulnerability templates (nuclei, nmap NSE)
- Header/SSL/TLS analysis
- Multi-agent pipeline: Recon → Analyst → Threat Intel → Validation → Remediation → Risk Manager → Reporter
- Deduplication by signature (scan_id, asset_id, title, port)
- Executive summary persisted per scan

### 4. Findings + CVE Correlation
- Central findings table with advanced filters
- Auto-correlation against: NVD 2.0 (CVSS v3.1/v3/v2), CPE aliases (~25 product mappings), EPSS, CISA KEV
- Bulk actions: mark as FP, accept risk, resolve
- Status history: open → in_progress → resolved → false_positive → accepted_risk
- Import from external scanners (JSON)

### 5. SSVC Prioritization (deterministic, 0 LLM tokens)
- Inputs: Exploitation (KEV-active → active, EPSS>0.9 → likely), Exposure (public vs internal), Technical Impact (CVSS), Automatable
- Output: Act / Attend / Track* / Track
- A CVSS 9.8 on an internal host with no public exploit → TRACK
- An actively exploited 7.5 on a public API → ACT
- Powers Dashboard "Act Now" counter

### 6. Watchtower (Continuous Threat Monitoring)
- Daily sync: CISA KEV, FIRST EPSS, NVD CVSS
- Persists asset software inventory from past scans
- Nightly re-correlation without re-scanning → new exposures found overnight
- EPSS spike detection (score jumps 0.2+ day-over-day)
- Auto-opens incidents for SSVC:Act findings
- Extended: ransomware victim tracking, dark web IOC feeds (ThreatFox, URLhaus)

### 7. Incidents / Case Management
- Group related findings into cases with owner + SLA
- States: open → in_progress → resolved → closed
- Timeline notes (team discussion)
- SLA countdown (red if overdue)
- Bidirectional links with findings
- Auto-created from SSVC:Act findings

### 8. Red/Blue Team (Adversarial AI Testing)
- AI agents simulate attacker (Red) and defender (Blue) perspectives
- Red Team generates attack findings: DNS spoofing, cert issues, exposed paths, known breaches, exploit attempts
- Blue Team generates defensive responses: patches applied, configs hardened, compensating controls
- Judge LLM arbitrates verdict + confidence calibration
- Finding categories: dns, ssl, headers, exposed_path, subdomain, breach, exploit, network
- Live streaming progress (SSE)
- Run history with metrics

### 9. Adversarial Validation (per finding)
- For ambiguous findings (confidence 0.2–0.9, no known exploit):
  - Red prompt: why this is a real risk
  - Blue prompt: why this is a false positive
  - Judge: verdict + calibrated confidence
- KEV-active findings bypass debate → auto-confirmed
- Verdicts persisted for future scans (memory)
- Cap: 15 debates per scan (configurable)

### 10. Community Verdicts (Federated Learning)
- Anonymous aggregation across all orgs
- k-anonymity: only published if ≥3 distinct orgs, ≥60% majority
- Priority chain: KEV > human prior > community prior > auto > debate
- New customers benefit from industry-learned FP suppression from day one

### 11. Phishing Simulation
- **Phishing Campaigns**: 4-step wizard (setup → assets → targets → review)
  - Templates: reusable or custom
  - Targets: employees, external contacts
  - Tracking: clicks, credential entry, reports
  - Objectives: click test, credential lure, reporting drill
  - Click tracking via public token URLs (no auth required)
  - PhishingAgent uses real asset inventory for credible lure context
- **Auth Phishing**: credential + MFA/OTP simulation, awareness reports
- Stats: sent / click rate / credential entry rate / report rate

### 12. Credential Exposure (HIBP)
- Have I Been Pwned domain search integration
- Employee breach lookup with karma score (how many times appeared)
- Sensitive breach badge (contains passwords/tokens)
- Correlation with asset access
- Background task polling + results table

### 13. Posture Timeline
- Deterministic risk score: Σ(open findings × severity weight) + KEV bonus
- Daily snapshots + annotated events (remediation, incident)
- Stacked area chart by severity over time
- Metrics: % criticals closed in 7d, open findings per asset
- Trend line (improving / degrading / stable)

### 14. Permission Policies
- Granular AI action controls: what agents can do automatically
- Conditions: asset_tags, is_internal_only, severity_max
- Modes: suggest_only / approval_required / auto
- Actions: update_library, apply_firewall_rule, restart_service, rotate_credentials, etc.

### 15. Schedules + Jobs
- Cron jobs for: recurring scans, discovery, CVE intel sync, Watchtower, posture snapshots
- Auto-retry on scan failure
- Full job execution history: type, status, trigger, duration, errors

### 16. Team + RBAC
- Invite by email, assign roles: admin / analyst / viewer
- Admin: full access
- Analyst: create/edit assets, trigger scans, approve suggestions, view findings
- Viewer: read-only

### 17. Audit Log
- Append-only, org-scoped log of all actions
- Actor types: user, agent, system
- Entities: assets, scans, findings, policies, team
- Filter by action / actor / entity

### 18. Integrations
- Slack: severity-filtered finding summaries
- Email: HTML/text reports
- PagerDuty: P1 for SSVC:Act
- OpsGenie: critical for SSVC:Act
- Jira: remediation tickets (roadmap)
- Webhook: generic POST to custom endpoint
- Per-integration test run with real secrets (server-side)

### 19. Dashboard
- Act Now (SSVC:Act count, pulsing if >0)
- KEV Exposure counter
- Asset Coverage % (green ≥80%, red <50%)
- MTTR Critical (days)
- Findings trend vs prior week
- SSVC priority grid
- Posture timeline + recent scans + top risky assets
- 11 toggleable widgets (persist in localStorage)

### 20. Privacy + Data Sovereignty
- Mode 1: No-cloud (LLM_ENABLED=false) — 100% local/deterministic
- Mode 2: Local model (Ollama/vLLM in your VPC)
- Mode 3: Cloud + redacted (hosts/IPs/emails pseudonymized before prompt)
- Mode 4: Cloud (not recommended)
- Bidirectional redaction map: responses de-redacted before display
- GDPR/HIPAA ready

### 21. API Keys
- Programmatic access with scoped keys
- Revoke without restart
- Scoped to user's role

---

## Buyer Personas

**Primary**: CISO / Security Manager at SMB (10–500 employees)
- Lean team, often 1 person doing SOC + AppSec + Risk
- Needs automation, not more noise
- Pain: manual triage of hundreds of "critical" findings

**Secondary**: Security Engineer at larger org
- Automate daily triage
- Needs granular control (permissions, integrations)
- Compliance gate: GDPR/HIPAA → data sovereignty required

**Tertiary**: MSP/MSSP
- Multi-tenant
- Needs credibility and white-label potential

---

## Key Differentiators

1. Zero-LLM deterministic core (CVE correlation, SSVC, Watchtower) — no hallucinations, no cost
2. Data sovereignty: 4 modes from fully local to cloud+redacted
3. SSVC over CVSS: real prioritization, not inflated scores
4. Watchtower: continuous monitoring without re-scanning
5. Adversarial validation: red/blue AI debate for ambiguous findings
6. Federated verdict learning: community FP suppression with k-anonymity
7. Configure once: discovery → scan → correlate → alert, all on schedule
8. Full audit trail: every AI decision is logged and explainable
