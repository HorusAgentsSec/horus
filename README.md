# Horus

AI-native cybersecurity platform for blue teams. A multi-agent LLM pipeline discovers your attack surface, scans for vulnerabilities, correlates findings against live threat intelligence, and surfaces only what needs your attention.

---

## Documentation

| | |
|---|---|
| [Overview](docs/overview.md) | Architecture, tech stack, deployment targets |
| [API Reference](docs/api-reference.md) | All REST endpoints with request/response shapes |
| [Agents](docs/agents.md) | Multi-agent pipeline stages, token budget, adversarial debate |
| [Scanners](docs/scanners.md) | Nmap, Nuclei, ZAP; CVE/EPSS/HIBP/IntelX threat intel; SSVC |
| [Data Models](docs/data-models.md) | Database schema, RLS policies, ERD |
| [Iris](docs/iris.md) | Rust monitoring daemon for your servers |
| [Security](docs/security.md) | Auth, roles, API keys, rate limiting, security headers |
| [Frontend](docs/frontend.md) | React app routes, layout, state management |
| [Deployment](docs/deployment.md) | Docker Compose, env vars, Fly.io, Cloudflare Pages |

---

## Architecture

```
  ┌──────────────────────────────────────────────────────────────┐
  │                        Horus Platform                        │
  │                                                              │
  │  React 18 PWA  ──────────────▶  FastAPI (Python)            │
  │  (Cloudflare Pages)            (Fly.io, single instance)     │
  │                                         │                    │
  │                           ┌─────────────┼─────────────┐     │
  │                           ▼             ▼             ▼     │
  │                       Supabase       Redis         APScheduler│
  │                    (Postgres+Auth) (rate limit)  (nightly jobs)│
  └──────────────────────────────────────────────────────────────┘

  Scan pipeline (triggered on-demand or on schedule):

  Assets ──▶ Recon ──▶ Analyst ──▶ Correlation ──▶ Threat Intel
                                                         │
              Reporter ◀── Risk Manager ◀── Remediation ◀── Validation

  Adversarial layer (parallel, per finding):
  Red Agent ◀──▶ Blue Agent ──▶ Verdict + confidence score

  Iris (optional, runs on your servers):
  JournaldMonitor + AuditdMonitor ──▶ Horus API ──▶ AI triage
```

---

## Quick Start

```bash
# 1. Copy and fill env vars
cp .env.example .env

# 2. Apply the migrations in your Supabase project (SQL editor)
#    Run each file in supabase/migrations/ in order

# 3. Start everything
docker-compose up
```

| Service | URL |
|---|---|
| Frontend | http://localhost:5173 |
| API | http://localhost:8000 |
| API docs (Swagger) | http://localhost:8000/docs |
| Mailpit (email previews) | http://localhost:8025 |

Full setup guide: [docs/deployment.md](docs/deployment.md)

---

## LLM Provider

The agent layer uses an OpenAI-compatible API, so any provider works:

```bash
# OpenRouter (access to Claude, GPT-4o, Llama, Mistral, etc.)
LLM_BASE_URL=https://openrouter.ai/api/v1
LLM_API_KEY=sk-or-...
LLM_DEFAULT_MODEL=anthropic/claude-opus-4-5

# Ollama (local, no data leaves your network)
LLM_BASE_URL=http://localhost:11434/v1
LLM_API_KEY=ollama
LLM_DEFAULT_MODEL=llama3.1:70b

# Per-agent overrides
LLM_REPORTER_MODEL=anthropic/claude-haiku-4-5
LLM_RISK_MANAGER_MODEL=anthropic/claude-haiku-4-5
```

---

## Data Privacy

The deterministic core (CVE correlation, SSVC, posture, Watchtower) never calls an LLM. Three operating modes:

| Mode | How | LLM calls |
|---|---|---|
| **Sovereign, no-cloud** | `LLM_ENABLED=false` | None |
| **Sovereign, local model** | Point `LLM_BASE_URL` at Ollama/vLLM in your VPC | Stay on-prem |
| **Private, cloud + redaction** | Default | Hostnames/IPs/emails pseudonymized before any prompt leaves the process |

Active mode is shown under **Settings → Data privacy**. Full guide: [docs/PRIVACY.md](docs/PRIVACY.md)

---

## Core Features

- **Attack surface discovery**: subdomain enumeration via CT logs and DNS brute-force, network CIDR sweeps
- **Vulnerability scanning**: Nmap (ports/services), Nuclei (templates), ZAP (DAST web)
- **Threat intelligence**: NVD CVE/CVSS/EPSS, CISA KEV, HIBP breaches, IntelX credentials, abuse.ch, ransomware.live
- **AI agent pipeline**: 8-stage pipeline with adversarial Red/Blue debate on ambiguous findings
- **Incident management**: case management with linked findings and append-only notes
- **Phishing simulation**: campaign builder, employee contacts, open/click tracking, community templates
- **Watchtower**: continuous monitoring for new CVEs affecting your software inventory
- **Iris**: lightweight Rust daemon that monitors your servers (journald + auditd) and reports back
- **Posture reporting**: security score over time, PDF export, email delivery

---

## Security Notes

- Supabase RLS is enforced on all tenant-owned tables; org isolation is handled at the policy layer, not application code.
- `SUPABASE_SERVICE_ROLE_KEY` is backend-only; never expose it to the browser.
- Scan targets are validated before execution to block private-address SSRF and shell injection.
- Rate limiting returns HTTP 429 with a `Retry-After` header. Redis is used when `REDIS_URL` is set; falls back to in-process memory.
- In production: set `ENVIRONMENT=production`, use HTTPS, rotate default secrets, and leave `TRUST_PROXY_HEADERS=false` unless behind a trusted proxy.

Full reference: [docs/security.md](docs/security.md)
