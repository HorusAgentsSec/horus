# Horus

AI-native cybersecurity platform for blue teams. A multi-agent LLM pipeline scans your infrastructure, enriches findings with threat intelligence, and suggests or auto-executes remediations — all gated by a granular permission system.

---

## Architecture

```
                        ┌─────────────────────────────────────────┐
                        │            Agent Pipeline                │
  ┌──────────┐          │                                         │
  │  Assets  │──scan──▶ │  Recon ──▶ Analyst ──▶ Threat Intel    │
  └──────────┘          │                 │                       │
                        │          Remediation ──▶ Risk Manager   │
  ┌──────────────────┐  │                 │                       │
  │ Permission       │──│─────────────────┘                       │
  │ Policies         │  │           Reporter                       │
  └──────────────────┘  └──────────────────┬──────────────────────┘
                                           │
                          ┌────────────────▼──────────────────┐
                          │         Supabase (PostgreSQL)      │
                          │  findings · agent_runs · suggestions│
                          └───────────────────────────────────┘
                                           │
                          ┌────────────────▼──────────────────┐
                          │    React 18 PWA (dark theme)       │
                          │  Realtime via Supabase channels    │
                          └───────────────────────────────────┘
```

---

## Agent Pipeline

Each agent receives only the state slice it needs — never full conversation history.

| Agent | Input | Output | LLM? |
|---|---|---|---|
| **Recon** | Asset host/port | `raw_findings` | No — subprocess only |
| **Analyst** | `raw_findings` | `analyzed_findings` (severity, fingerprint, CVSS) | Yes |
| **Threat Intel** | `analyzed_findings` titles+CVEs | `enriched_findings` (exploitability, context) | Yes |
| **Remediation** | analyzed + enriched findings | `remediation_suggestions` (commands, patches) | Yes |
| **Risk Manager** | suggestions + permission_rules | `risk_decisions` (auto/approval/suggest) | LLM fallback only |
| **Reporter** | counts + top 10 findings | `ScanReport` summary | Yes |

---

## Quick Start

```bash
# 1. Copy and fill env vars
cp .env.example .env

# 2. Run the migration in your Supabase project
# Paste supabase/migrations/001_initial.sql into the SQL editor

# 3. Start everything
docker-compose up
```

Frontend: http://localhost:5173  
API: http://localhost:8000  
API docs: http://localhost:8000/docs

---

## LLM Provider Configuration

The agent layer uses the OpenAI-compatible API, so any provider works:

```bash
# OpenRouter (recommended — access to Claude, GPT-4o, Llama, Mistral, etc.)
LLM_BASE_URL=https://openrouter.ai/api/v1
LLM_API_KEY=sk-or-...
LLM_DEFAULT_MODEL=anthropic/claude-opus-4-5

# Ollama (local models, no API key needed)
LLM_BASE_URL=http://localhost:11434/v1
LLM_API_KEY=ollama
LLM_DEFAULT_MODEL=llama3.1:70b

# Per-agent overrides (e.g. use a fast model for the reporter)
LLM_REPORTER_MODEL=anthropic/claude-haiku-4-5
LLM_RISK_MANAGER_MODEL=anthropic/claude-haiku-4-5
```

---

## Data privacy & deployment modes

A security tool shouldn't leak your infrastructure map to a third party. The deterministic core
(CVE correlation, SSVC, posture, Watchtower) **never calls an LLM**, so Horus can run with
your data fully inside your perimeter:

- **Sovereign — no-cloud** (`LLM_ENABLED=false`): the whole pipeline runs with zero LLM calls.
- **Sovereign — local model**: point `LLM_BASE_URL` at Ollama/vLLM in your VPC; nothing leaves.
- **Private — cloud + redaction** (default): hostnames/IPs/emails are pseudonymized before any prompt
  leaves the process and restored in the response.

The active posture is shown under **Settings → Data privacy**. Full guide: **[docs/PRIVACY.md](docs/PRIVACY.md)**.

---

## Adding Scan Targets

1. Go to **Assets** → Add Asset
2. Enter host (e.g. `example.com`), type (`web`, `ip`, `api`, `domain`), and tags
3. Click **Scan now** on any asset row, or configure a schedule in **Settings**

Or via API:
```bash
curl -X POST http://localhost:8000/api/assets \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"My App","host":"app.example.com","type":"web","tags":["production"]}'
```

---

## Permission Policies

Policies control what the AI is allowed to do automatically.

Go to **Permissions** → New Policy → add rules:

| Action | Mode | Meaning |
|---|---|---|
| `update_library` | `auto` | Agent updates packages without asking |
| `apply_firewall_rule` | `approval_required` | Agent proposes, human approves |
| `restart_service` | `suggest_only` | Agent only suggests, never executes |

Rules support conditions:
- `asset_tags`: only apply to assets with these tags
- `is_internal_only`: only apply to internal assets
- `severity_max`: only apply when finding severity is at or below this level

---

## Running the Pipeline Manually via API

```bash
# Trigger a scan
curl -X POST http://localhost:8000/api/scans \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"asset_id":"<uuid>","tools":["nuclei","nmap"]}'

# Check status + agent run timeline
curl http://localhost:8000/api/scans/<scan_id> \
  -H "Authorization: Bearer $TOKEN"

# List findings with filters
curl "http://localhost:8000/api/findings?severity=critical&status=open" \
  -H "Authorization: Bearer $TOKEN"

# Approve a suggestion
curl -X POST http://localhost:8000/api/suggestions/<id>/approve \
  -H "Authorization: Bearer $TOKEN"
```

---

## Environment Variables Reference

Keep backend and browser secrets separate. Only `VITE_*` values are bundled into
the frontend; never put the Supabase service-role key, LLM keys, or integration
secrets in `frontend/.env` or any variable prefixed with `VITE_`.

| Variable | Required | Description |
|---|---|---|
| `SUPABASE_URL` | Yes | Your Supabase project URL |
| `SUPABASE_ANON_KEY` | Yes | Supabase anon key |
| `SUPABASE_SERVICE_ROLE_KEY` | Yes | Supabase service role key (backend only) |
| `LLM_BASE_URL` | Yes | OpenAI-compatible endpoint |
| `LLM_API_KEY` | Yes | API key for the provider |
| `LLM_DEFAULT_MODEL` | Yes | Default model for all agents |
| `LLM_TIMEOUT_SECONDS` | No | Per-call LLM timeout in seconds |
| `LLM_MAX_RETRIES` | No | Retries for transient LLM/provider failures |
| `LLM_ANALYST_MODEL` | No | Override model for Analyst agent |
| `LLM_THREAT_INTEL_MODEL` | No | Override model for Threat Intel agent |
| `LLM_REMEDIATION_MODEL` | No | Override model for Remediation agent |
| `LLM_RISK_MANAGER_MODEL` | No | Override model for Risk Manager agent |
| `LLM_REPORTER_MODEL` | No | Override model for Reporter agent |
| `PIPELINE_MAX_CONCURRENCY` | No | Maximum scans running concurrently per backend process |
| `ENVIRONMENT` | No | `development`, `staging`, or `production`; controls security headers such as HSTS |
| `SECRET_KEY` | Yes | App secret; replace the default before deployment |
| `RATE_LIMIT_ENABLED` | No | Enables in-memory rate limiting for `/api` routes |
| `RATE_LIMIT_PER_MINUTE` | No | Per-IP request budget across all `/api` routes |
| `RATE_LIMIT_SENSITIVE_PER_MINUTE` | No | Tighter per-IP budget for scan trigger and team invite routes |
| `TRUST_PROXY_HEADERS` | No | Honor `X-Forwarded-For`; set true only behind a trusted reverse proxy |
| `SHODAN_API_KEY` | No | Shodan integration (optional) |
| `VITE_SUPABASE_URL` | Yes (frontend) | Supabase URL for the browser client |
| `VITE_SUPABASE_ANON_KEY` | Yes (frontend) | Supabase anon key for the browser |

---

## Security Notes

- Supabase RLS is enabled for tenant-owned tables. User-facing backend queries use
  an authed Supabase client so org isolation is enforced by policy.
- `SUPABASE_SERVICE_ROLE_KEY` is reserved for backend-only system writes, such as
  append-only audit logging. Do not expose it to the browser.
- Asset create, update, and delete actions write audit events with actor, org,
  entity id, and compact metadata for incident review.
- Scan targets are validated before persistence or execution to block metadata
  endpoints, private addresses unless explicitly marked internal, and shell/flag
  injection patterns.
- API rate limiting returns HTTP `429` with a `Retry-After` header. The frontend
  converts that into user-facing wait guidance.
- In production, set `ENVIRONMENT=production`, use HTTPS, rotate default secrets,
  keep JWT lifetimes appropriate for your risk model, and leave
  `TRUST_PROXY_HEADERS=false` unless your deployment terminates traffic at a
  trusted proxy that controls `X-Forwarded-For`.
