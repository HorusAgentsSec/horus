# Horus: Overview

## What Horus is

Horus is an AI-native security automation platform for small IT teams. It runs a multi-agent pipeline that discovers your attack surface, scans for vulnerabilities, enriches findings against live threat intelligence, debates ambiguous results with adversarial LLM agents, and surfaces only the handful of things that actually need your attention. The deterministic core (CVE correlation, SSVC scoring, Watchtower exposure monitoring) never calls an LLM, so it can run fully air-gapped. The LLM layer is optional, provider-agnostic (any OpenAI-compatible endpoint), and redacts hostnames, IPs, and emails from prompts before they leave the process. You configure it once; scheduled jobs run every night without anyone on-call.

---

## Who it's for

Primary audience: small IT teams of 1 to 3 people at startups and SMBs. Typically a DevOps engineer or an "accidental CISO" who is also responsible for security. They know enough to be worried but do not have time to triage hundreds of alerts per week.

Secondary audience: security-curious founders or CTOs at early-stage companies who want automated coverage without hiring a dedicated security function.

Horus is not designed for dedicated security analysts or red-team operators. It is a blue-team force-multiplier for people who need the coverage of a 5-person security function with a team of two.

---

## Core capabilities

- **Attack surface discovery:** passive subdomain enumeration via certificate transparency logs (crt.sh, Certspotter), DNS brute-force of common labels, and active network sweep for internal CIDRs. Shodan integration is optional.
- **Vulnerability scanning:** Nmap and Nuclei are the primary scan tools. Assets are classified as `web`, `ip`, `api`, or `domain`. Scan targets are validated against a blocklist of metadata endpoints, private addresses, and injection patterns before execution.
- **Threat intelligence correlation:** findings are enriched against CISA KEV and FIRST EPSS (synced daily). CVE-to-CPE correlation queries the NVD API on demand with a 7-day local cache. IOC feeds from abuse.ch (ThreatFox, URLhaus) and ransomware.live are checked on a separate daily schedule.
- **Adversarial AI debate (red/blue):** ambiguous findings go through a red agent (attacker perspective) and a blue agent (defender perspective) that debate severity and exploitability. Deterministic triage resolves clear-cut findings for free; only the ambiguous ones reach the LLM, capped per scan to control cost.
- **Incident management:** findings promote to incidents with case lifecycle tracking, notes, and audit trail. Every asset create/update/delete writes an immutable audit event.
- **Phishing simulation:** an LLM-driven PhishingAgent generates targeted phishing campaigns with honeypot tracking links. Results feed back into the findings and incident pipeline.
- **Watchtower:** a daily job that re-correlates each asset's persisted software inventory against newly known-exploited CVEs without re-scanning. Also alerts on EPSS spikes (exploitation probability jumps day-over-day). This is what turns a one-off scan into continuous coverage.
- **Iris daemon (host agent):** a lightweight Rust daemon (`iris-rs`) that runs on monitored hosts. It reports system events to the backend, which runs AI triage every 15 minutes. Hosts that stop reporting are flagged offline and trigger an alert.

---

## Architecture overview

```
Browser (React/Vite SPA)
        |
        | HTTPS
        v
FastAPI backend  ─── Supabase Postgres (RLS-enforced, per-org)
        |                     |
        |           Supabase Auth (JWT)
        |
   APScheduler (in-process)
        |
        +── Nightly scan jobs
        +── CVE/KEV/EPSS sync   (daily 05:00)
        +── Watchtower           (daily 05:30)
        +── HIBP credential check (daily 03:00)
        +── Adversarial debate   (daily 02:00)
        +── IOC feed checks      (daily 06:00)
        +── Ransomware.live check (daily 06:30)
        +── Posture snapshots    (daily 06:00)
        +── Iris triage poll     (every 15 min)
        |
   LLM layer (OpenAI-compatible endpoint; optional)
        |
        +── Analyst team (parallel domain specialists: web / network / TLS)
        +── Threat Intel agent
        +── Remediation agent
        +── Risk Manager (permission-gated auto/approval/suggest)
        +── Reporter
        +── Red/Blue adversarial agents
        +── PhishingAgent
        |
   Iris Rust daemon (host agent, deployed per monitored host)
```

The frontend communicates with the backend exclusively through the REST API at `/api/*`. Supabase Realtime is used for live scan progress updates. All tenant data is isolated at the database layer via Row Level Security policies; user-facing backend queries use an authed Supabase client so org isolation is enforced by policy, not application code.

APScheduler runs inside the FastAPI process. Because of this, the backend must not be scaled to more than one machine: a second instance would run duplicate scheduled jobs. See the deployment notes below.

---

## Tech stack

| Layer | Technology |
|---|---|
| Backend | Python 3.12, FastAPI, Uvicorn, Pydantic v2, APScheduler |
| Frontend | React 18, Vite, TypeScript, React Router, Tailwind CSS |
| Database | Supabase (PostgreSQL), Row Level Security for multi-tenancy |
| Auth | Supabase Auth (JWT); service-role key is backend-only |
| Rate limiting | In-process sliding window; Redis-backed when `REDIS_URL` is set |
| LLM provider | Any OpenAI-compatible endpoint (OpenRouter, Ollama, vLLM, etc.) |
| Host agent | Rust (`iris-rs`); compiled binary deployed to monitored hosts |
| Local email (dev) | Mailpit (SMTP + web UI on port 8025) |
| Deployment: API | Fly.io (`horus-api`, `shared-cpu-1x`, 512 MB, `cdg` region) |
| Deployment: frontend | Cloudflare Pages (`app.horusagents.com`) |
| Deployment: database | Supabase managed Postgres |

---

## Deployment targets

### Local development (Docker Compose)

Three services: `backend` (port 8000), `frontend` Vite dev server (port 5173), and `mailpit` for local SMTP testing (port 8025 for the web UI). The frontend proxies `/api/*` to the backend via Vite's dev-server proxy.

```bash
cp .env.example .env   # fill in Supabase URL/keys and LLM credentials
docker-compose up
```

API docs are available at `http://localhost:8000/docs`.

### Production

| Component | Target | Notes |
|---|---|---|
| API | Fly.io app `horus-api`, region `cdg` | `auto_stop_machines = false`; APScheduler requires the process to stay alive. Do not scale to 2+ machines. |
| Frontend | Cloudflare Pages | Served at `app.horusagents.com`. Build output from `npm run build` in `frontend/`. |
| Database | Supabase | Migrations applied manually via the SQL editor (schema history is diverged from `db push`). See `docs/` for migration state. |

### Data privacy modes

Three postures are supported, controlled by env vars:

- **Sovereign, no-cloud** (`LLM_ENABLED=false`): zero LLM calls. The entire pipeline runs deterministically.
- **Sovereign, local model**: point `LLM_BASE_URL` at Ollama or vLLM inside your VPC. Nothing leaves the perimeter.
- **Private, cloud with redaction** (default): hostnames, IPs, and emails are pseudonymized in every prompt before the request leaves the process. The mapping is restored in the response.

The active posture is visible under **Settings > Data privacy**.
