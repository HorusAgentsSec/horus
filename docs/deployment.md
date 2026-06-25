# Deployment Guide

This document covers everything needed to run Horus: local development with Docker Compose, the full environment variable reference, and production deployment across Fly.io (backend), Cloudflare Pages (frontend), and Supabase.

---

## Table of contents

1. [Local development](#local-development)
2. [Environment variable reference](#environment-variable-reference)
3. [Production deployment](#production-deployment)
   - [Backend on Fly.io](#backend-on-flyio)
   - [Frontend on Cloudflare Pages](#frontend-on-cloudflare-pages)
   - [Supabase](#supabase)
4. [Redis and rate limiting](#redis-and-rate-limiting)
5. [Health check](#health-check)
6. [Security headers](#security-headers)
7. [Scaling constraints](#scaling-constraints)

---

## Local development

The project ships a `docker-compose.yml` at the repo root. It starts three services:

| Service | Port | Description |
|---------|------|-------------|
| `backend` | `8000` | FastAPI app with hot-reload via Uvicorn |
| `frontend` | `5173` | Vite dev server (proxies API calls to the backend) |
| `mailpit` | `1025` (SMTP), `8025` (web UI) | Local email catcher; no real mail is sent |

### Start everything

```bash
# Copy the example env file and fill in the required values (see the reference below)
cp .env.example .env

docker compose up
```

The backend mounts `./backend` into the container, so code changes reload automatically without rebuilding the image.

### Useful shortcuts

```bash
# Backend only (no frontend, no mail)
docker compose up backend

# Tail logs from all services
docker compose logs -f

# Rebuild after changing requirements.txt or the Dockerfile
docker compose build backend
docker compose up
```

### What the frontend proxy does

In development, Vite forwards any request that starts with `/api` to `http://backend:8000` via the `VITE_API_PROXY_TARGET` environment variable. You never need to hard-code the backend URL in the frontend during local development.

---

## Environment variable reference

All variables are loaded from a `.env` file in the project root (or from real environment variables in production). The backend uses Pydantic Settings; unknown keys are silently ignored.

### Supabase (required)

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `SUPABASE_URL` | Yes | Your Supabase project URL | `https://abcdefgh.supabase.co` |
| `SUPABASE_ANON_KEY` | Yes | Public anon key (safe to expose to the browser) | `eyJhbGciOiJIUzI1NiIs...` |
| `SUPABASE_SERVICE_ROLE_KEY` | Yes | Service role key (server-side only, never sent to the browser) | `eyJhbGciOiJIUzI1NiIs...` |

### LLM provider

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `LLM_BASE_URL` | No | OpenAI-compatible API base URL | `https://openrouter.ai/api/v1` |
| `LLM_API_KEY` | No | API key for the LLM provider | `sk-or-v1-...` |
| `LLM_DEFAULT_MODEL` | No | Model string used by all agents unless overridden | `anthropic/claude-opus-4-5` |
| `LLM_TIMEOUT_SECONDS` | No | Per-request timeout in seconds (default: `60.0`) | `60.0` |
| `LLM_MAX_RETRIES` | No | Retry count for transient LLM errors (default: `2`) | `2` |
| `LLM_ENABLED` | No | Set to `false` for fully deterministic, no-cloud mode (default: `true`) | `false` |

Per-agent model overrides (all optional; fall back to `LLM_DEFAULT_MODEL`):

| Variable | Agent |
|----------|-------|
| `LLM_ANALYST_MODEL` | Domain analyst |
| `LLM_THREAT_INTEL_MODEL` | Threat intel |
| `LLM_VALIDATION_MODEL` | Red/blue debate validator |
| `LLM_REMEDIATION_MODEL` | Remediation drafter |
| `LLM_RISK_MANAGER_MODEL` | Risk manager |
| `LLM_REPORTER_MODEL` | Report generator |
| `LLM_RED_MODEL` | Red adversarial agent |
| `LLM_BLUE_MODEL` | Blue adversarial agent |
| `LLM_PHISHING_MODEL` | Phishing simulation agent |
| `LLM_IRIS_TRIAGE_MODEL` | Iris AI triage |

### Application

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `ENVIRONMENT` | No | `development` or `production`; controls HSTS and other headers (default: `development`) | `production` |
| `SECRET_KEY` | Yes (prod) | Secret used for signing; change from the default `changeme` before deploying | `a-long-random-string` |

### Rate limiting

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `RATE_LIMIT_ENABLED` | No | Toggle all rate limiting (default: `true`) | `true` |
| `RATE_LIMIT_PER_MINUTE` | No | Per-IP request budget for all `/api` routes (default: `120`) | `120` |
| `RATE_LIMIT_SENSITIVE_PER_MINUTE` | No | Tighter budget for write-heavy endpoints like `POST /api/scans` (default: `10`) | `10` |
| `TRUST_PROXY_HEADERS` | No | Honor `X-Forwarded-For` when behind a trusted reverse proxy (default: `false`) | `true` |
| `REDIS_URL` | No | Redis connection string; enables shared rate-limit state across workers. Falls back to per-process in-memory when unset. | `redis://localhost:6379/0` |

### Scan pipeline

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `PIPELINE_MAX_CONCURRENCY` | No | Maximum number of scans running in parallel (default: `2`) | `2` |
| `SCAN_MAX_RETRIES` | No | Auto-retry count for failed scheduled scans (default: `1`) | `1` |
| `SCAN_BLACKOUT_WINDOWS` | No | Comma-separated time ranges when scheduled scans are skipped | `Mon-Fri 09:00-18:00` |
| `SCAN_BLACKOUT_TIMEZONE` | No | IANA timezone for blackout windows (default: server local time) | `Europe/Madrid` |

### CVE and vulnerability intelligence

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `CVE_SYNC_ENABLED` | No | Enable daily CISA KEV and EPSS sync (default: `true`) | `true` |
| `CVE_SYNC_CRON` | No | Cron schedule for CVE sync (default: `0 5 * * *`) | `0 5 * * *` |
| `CVE_SYNC_INCLUDE_EPSS` | No | Include EPSS scores (~250k rows); disable in dev to save time (default: `true`) | `false` |
| `NVD_API_KEY` | No | NVD API key; raises rate limit from 5 to 50 req/30s. Get one free at nvd.nist.gov. | `abc123-...` |

### Notifications

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `SMTP_HOST` | No | SMTP server hostname for email notifications | `smtp.resend.com` |
| `SMTP_PORT` | No | SMTP port (default: `587`) | `587` |
| `SMTP_USER` | No | SMTP username | `apikey` |
| `SMTP_PASSWORD` | No | SMTP password or API key | `re_...` |
| `SMTP_FROM` | No | Sender address | `alerts@yourdomain.com` |
| `SMTP_USE_TLS` | No | Enable STARTTLS (default: `true`) | `true` |
| `NOTIFY_DEFAULT_MIN_SEVERITY` | No | Minimum severity to trigger a notification (default: `high`) | `medium` |

### Optional integrations

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `SHODAN_API_KEY` | No | Shodan API key for enriched asset data | `abc123...` |
| `HIBP_API_KEY` | No | HaveIBeenPwned Domain Search API key; HIBP checks are disabled without it | `abc123...` |
| `TAVILY_API_KEY` | No | Tavily web search key used by the adversarial agents | `tvly-...` |
| `GITHUB_TOKEN` | No | GitHub personal access token for exploit/PoC searches (rate-limit is 10 req/min without one) | `ghp_...` |

### Privacy and data controls

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `REDACTION_ENABLED` | No | Pseudonymize hostnames, IPs, and emails in prompts before they leave the process (default: `true`) | `true` |

---

## Production deployment

### Backend on Fly.io

The backend runs as a single Fly.io machine in the `cdg` (Paris) region.

**Important: do not scale to more than one machine.** APScheduler runs inside the process and owns all scheduled jobs (CVE sync, Watchtower, Iris triage, etc.). Running two machines simultaneously would fire every job twice. See [Scaling constraints](#scaling-constraints) for details.

#### fly.toml summary

```toml
app = "horus-api"
primary_region = "cdg"

[http_service]
  internal_port = 8000
  force_https = true
  auto_stop_machines = false   # never sleep; APScheduler must keep running
  auto_start_machines = true
  min_machines_running = 1

[[vm]]
  size = "shared-cpu-1x"
  memory = "512mb"
```

`auto_stop_machines = false` is intentional: the scheduler fires overnight jobs (HIBP check at 03:00, CVE sync at 05:00, Watchtower at 05:30, posture snapshot at 06:00). If the machine sleeps, those jobs do not run.

#### Set secrets

```bash
# Required
fly secrets set SUPABASE_URL="https://abcdefgh.supabase.co"
fly secrets set SUPABASE_ANON_KEY="eyJ..."
fly secrets set SUPABASE_SERVICE_ROLE_KEY="eyJ..."
fly secrets set LLM_API_KEY="sk-or-v1-..."
fly secrets set SECRET_KEY="$(openssl rand -hex 32)"
fly secrets set ENVIRONMENT="production"

# Optional but recommended
fly secrets set NVD_API_KEY="..."
fly secrets set HIBP_API_KEY="..."
```

#### Deploy

```bash
# First deploy (from the repo root)
fly deploy

# Subsequent deploys
fly deploy

# Check status
fly status
fly logs
```

The deploy command uses `backend/Dockerfile` with the project root as build context (matching `docker-compose.yml`). The image bundles nmap and a pre-fetched copy of Nuclei templates so the first scan does not pay a download cost.

#### Verify the deploy

```bash
curl https://horus-api.fly.dev/health
# {"status": "ok"}
```

### Frontend on Cloudflare Pages

The frontend is a Vite + React SPA deployed to Cloudflare Pages at `app.horusagents.com`.

#### Build settings (in the Cloudflare Pages dashboard)

| Setting | Value |
|---------|-------|
| Framework preset | None (custom) |
| Build command | `npm run build` |
| Build output directory | `dist` |
| Root directory | `frontend` |

#### Environment variables (set in Pages settings)

| Variable | Value |
|----------|-------|
| `VITE_API_URL` | `https://horus-api.fly.dev` |
| `VITE_SUPABASE_URL` | Your Supabase project URL |
| `VITE_SUPABASE_ANON_KEY` | Your Supabase anon key |

`VITE_API_URL` is baked into the bundle at build time by Vite. Make sure it does not have a trailing slash.

#### Deploy

Every push to `main` triggers an automatic build and deploy via the Cloudflare Pages Git integration.

### Supabase

Horus uses Supabase for:

- **Postgres**: primary database for all application data (assets, scans, findings, orgs, users).
- **Auth**: handles sign-up, login, sessions, and JWT issuance via GoTrue. GoTrue has its own built-in throttling for auth endpoints.
- **Row Level Security (RLS)**: every table has RLS policies enforced at the database level. All data is scoped to the authenticated user's organization; soft-delete is enforced via `deleted_at` on all entities (nothing is hard-deleted).

Supabase is managed infrastructure; there is no self-hosted Supabase component. All schema changes are applied manually via the Supabase SQL editor because `db push` is blocked (divergent migration history). See `memory/project_migrations_state.md` for details.

---

## Redis and rate limiting

Redis is optional. When `REDIS_URL` is set and Redis is reachable at startup, the backend uses a Redis-backed sliding-window limiter (atomic via a Lua script). This is the correct choice for any deployment where more than one worker process runs, because rate-limit state is shared across all workers.

When `REDIS_URL` is not set, or when Redis is unreachable at startup, the backend automatically falls back to a per-process in-memory limiter and logs a warning. Under the current Fly.io deployment (single machine, single Uvicorn process), the in-memory fallback is functionally equivalent.

Default budgets (all configurable via env vars):

| Scope | Default |
|-------|---------|
| All `/api` routes, per IP, per minute | 120 requests |
| `POST /api/scans` and `POST /api/team/invite`, per IP, per minute | 10 requests |

A rate-limited request receives HTTP 429 with a `Retry-After` header.

---

## Health check

```
GET /health
```

Returns `{"status": "ok"}` with HTTP 200. No authentication required.

Fly.io polls this endpoint every 30 seconds with a 5-second timeout and a 20-second grace period on startup. A failing health check causes Fly to restart the machine.

You can use this endpoint for uptime monitoring:

```bash
curl https://horus-api.fly.dev/health
```

---

## Security headers

The backend attaches security headers to every response. The header set is the same in development and production, with one exception: `Strict-Transport-Security` is only sent outside development to avoid forcing HTTPS on a plaintext localhost connection.

| Header | Value | Notes |
|--------|-------|-------|
| `X-Content-Type-Options` | `nosniff` | Prevents MIME sniffing |
| `X-Frame-Options` | `DENY` | Blocks the API from being embedded in a frame |
| `Referrer-Policy` | `no-referrer` | Prevents leaking API URLs (which may carry IDs) to other origins |
| `Content-Security-Policy` | `default-src 'none'; frame-ancestors 'none'` | Locks down responses to JSON only; nothing can be loaded or framed |
| `Cross-Origin-Opener-Policy` | `same-origin` | Isolates the browsing context group |
| `Permissions-Policy` | `geolocation=(), camera=(), microphone=(), payment=()` | Revokes access to powerful browser features |
| `Strict-Transport-Security` | `max-age=31536000; includeSubDomains` | **Production only.** Forces HTTPS for one year including subdomains. |

---

## Scaling constraints

**The backend must run as a single instance.**

APScheduler is embedded in the FastAPI process. It holds the state for all scheduled jobs:

- HIBP credential breach check (daily 03:00)
- CVE/KEV sync from CISA and EPSS (daily 05:00)
- Watchtower exposure re-correlation (daily 05:30)
- Posture snapshot (daily 06:00)
- Monthly posture report (1st of month, 07:00)
- Ransomware.live check (daily 06:30)
- Adversarial agent run (daily 02:00)
- Iris AI triage polling (every 15 minutes)

Running two machines would fire every job twice, produce duplicate alerts, and create race conditions in the database. The `fly.toml` configuration enforces this with `min_machines_running = 1` and `auto_stop_machines = false`.

If you need to handle more concurrent scan throughput, increase `PIPELINE_MAX_CONCURRENCY` rather than adding machines. The scan queue will absorb demand up to that concurrency limit within the single process.

If you eventually need true horizontal scaling, APScheduler would need to be replaced with a distributed job scheduler (for example, pg_cron via Supabase, or a dedicated queue backed by Redis).
