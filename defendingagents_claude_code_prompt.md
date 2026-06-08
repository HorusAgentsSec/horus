# DefendingAgents — Claude Code Build Prompt

## Context

Build **DefendingAgents**: an AI-native cybersecurity platform for blue teams. The core idea is a multi-agent LLM pipeline (inspired by TradingAgents — arxiv.org/pdf/2412.20138) where specialized agents collaborate to scan infrastructure, analyze vulnerabilities, enrich findings with threat intelligence, and suggest or auto-execute remediations — all gated by a granular permission system.

This is not a wrapper around DefectDojo. The differentiation is that agents are active and opinionated, not passive aggregators.

---

## Tech Stack

- **Backend**: FastAPI (Python 3.12)
- **Agent layer**: Anthropic SDK (`anthropic` Python package) — no LangChain
- **Frontend**: React 18 + Vite + TailwindCSS + shadcn/ui — built as a PWA
- **Database + Auth**: Supabase (PostgreSQL + Supabase Auth + Realtime)
- **Background jobs**: APScheduler (in-process, simple)
- **Scan tools**: subprocess wrappers around Nuclei, Nmap, OWASP ZAP
- **Token optimization**: structured Pydantic outputs between agents; agents receive only their state slice, never full conversation history

---

## Project Structure

Create the following directory and file structure exactly:

```
defendingagents/
├── .env.example
├── .gitignore
├── docker-compose.yml
├── README.md
│
├── backend/
│   ├── requirements.txt
│   ├── main.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   ├── supabase_client.py
│   │   └── scheduler.py
│   ├── api/
│   │   ├── __init__.py
│   │   ├── router.py
│   │   ├── assets.py
│   │   ├── scans.py
│   │   ├── findings.py
│   │   ├── agents.py
│   │   ├── permissions.py
│   │   └── auth.py
│   ├── agents/
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── state.py
│   │   ├── pipeline.py
│   │   ├── recon_agent.py
│   │   ├── analyst_agent.py
│   │   ├── threat_intel_agent.py
│   │   ├── remediation_agent.py
│   │   ├── risk_manager_agent.py
│   │   └── reporter_agent.py
│   ├── scanners/
│   │   ├── __init__.py
│   │   ├── base_scanner.py
│   │   ├── nuclei_scanner.py
│   │   ├── nmap_scanner.py
│   │   └── zap_scanner.py
│   └── models/
│       ├── __init__.py
│       └── schemas.py
│
├── frontend/
│   ├── package.json
│   ├── vite.config.ts
│   ├── tailwind.config.ts
│   ├── tsconfig.json
│   ├── index.html
│   ├── public/
│   │   ├── manifest.json
│   │   └── sw.js
│   └── src/
│       ├── main.tsx
│       ├── App.tsx
│       ├── lib/
│       │   ├── supabase.ts
│       │   ├── api.ts
│       │   └── utils.ts
│       ├── hooks/
│       │   ├── useAuth.ts
│       │   ├── useRealtime.ts
│       │   └── useAssets.ts
│       ├── components/
│       │   ├── layout/
│       │   │   ├── Sidebar.tsx
│       │   │   ├── Header.tsx
│       │   │   └── Layout.tsx
│       │   ├── ui/         ← shadcn components go here
│       │   ├── findings/
│       │   │   ├── FindingCard.tsx
│       │   │   ├── FindingDetail.tsx
│       │   │   └── SeverityBadge.tsx
│       │   ├── agents/
│       │   │   ├── AgentRunTimeline.tsx
│       │   │   └── SuggestionCard.tsx
│       │   └── assets/
│       │       ├── AssetForm.tsx
│       │       └── AssetList.tsx
│       └── pages/
│           ├── Login.tsx
│           ├── Dashboard.tsx
│           ├── Assets.tsx
│           ├── Scans.tsx
│           ├── Findings.tsx
│           ├── FindingDetail.tsx
│           ├── Permissions.tsx
│           └── Settings.tsx
│
└── supabase/
    └── migrations/
        └── 001_initial.sql
```

---

## Database — `supabase/migrations/001_initial.sql`

```sql
-- Enable UUID extension
create extension if not exists "uuid-ossp";

-- Organizations
create table organizations (
  id uuid primary key default uuid_generate_v4(),
  name text not null,
  settings jsonb default '{}',
  created_at timestamptz default now()
);

-- Profiles (extends Supabase auth.users)
create table profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  org_id uuid references organizations(id) on delete cascade,
  role text not null default 'analyst' check (role in ('admin', 'analyst', 'viewer')),
  full_name text,
  created_at timestamptz default now()
);

-- Assets (targets to scan)
create table assets (
  id uuid primary key default uuid_generate_v4(),
  org_id uuid references organizations(id) on delete cascade not null,
  name text not null,
  host text not null,
  port integer,
  type text not null check (type in ('web', 'ip', 'api', 'domain')),
  is_internal boolean default false,
  is_active boolean default true,
  tags text[] default '{}',
  metadata jsonb default '{}',
  created_at timestamptz default now()
);

-- Scan schedules
create table scan_schedules (
  id uuid primary key default uuid_generate_v4(),
  org_id uuid references organizations(id) on delete cascade not null,
  name text not null,
  asset_ids uuid[] not null,
  cron_expression text not null default '0 2 * * *',
  tools text[] not null default '{nuclei,nmap}',
  enabled boolean default true,
  last_run_at timestamptz,
  next_run_at timestamptz,
  created_at timestamptz default now()
);

-- Scans
create table scans (
  id uuid primary key default uuid_generate_v4(),
  org_id uuid references organizations(id) on delete cascade not null,
  asset_id uuid references assets(id) on delete cascade not null,
  schedule_id uuid references scan_schedules(id) on delete set null,
  status text not null default 'pending' check (status in ('pending', 'running', 'completed', 'failed')),
  tools_used text[] default '{}',
  triggered_by text not null default 'schedule',
  raw_output jsonb default '{}',
  error_message text,
  started_at timestamptz,
  completed_at timestamptz,
  created_at timestamptz default now()
);

-- Findings (deduplicated vulnerabilities)
create table findings (
  id uuid primary key default uuid_generate_v4(),
  org_id uuid references organizations(id) on delete cascade not null,
  scan_id uuid references scans(id) on delete set null,
  asset_id uuid references assets(id) on delete cascade not null,
  title text not null,
  description text,
  severity text not null check (severity in ('critical', 'high', 'medium', 'low', 'info')),
  cvss_score numeric(4,1),
  cve_ids text[] default '{}',
  status text not null default 'open' check (status in ('open', 'in_progress', 'resolved', 'false_positive', 'accepted_risk')),
  fingerprint text not null,
  raw_data jsonb default '{}',
  first_seen_at timestamptz default now(),
  last_seen_at timestamptz default now(),
  created_at timestamptz default now(),
  unique(org_id, fingerprint)
);

-- Agent runs (one per agent per pipeline execution)
create table agent_runs (
  id uuid primary key default uuid_generate_v4(),
  org_id uuid references organizations(id) on delete cascade not null,
  scan_id uuid references scans(id) on delete cascade,
  finding_id uuid references findings(id) on delete cascade,
  agent_type text not null check (agent_type in ('recon', 'analyst', 'threat_intel', 'remediation', 'risk_manager', 'reporter')),
  status text not null default 'running' check (status in ('running', 'completed', 'failed')),
  input_state jsonb default '{}',
  output_state jsonb default '{}',
  tokens_used integer default 0,
  model_used text,
  error_message text,
  started_at timestamptz default now(),
  completed_at timestamptz
);

-- Agent suggestions (what the AI proposes to do)
create table agent_suggestions (
  id uuid primary key default uuid_generate_v4(),
  org_id uuid references organizations(id) on delete cascade not null,
  finding_id uuid references findings(id) on delete cascade not null,
  agent_run_id uuid references agent_runs(id) on delete cascade,
  action_type text not null,
  title text not null,
  description text not null,
  command_or_patch text,
  confidence_score numeric(3,2) check (confidence_score between 0 and 1),
  estimated_risk text check (estimated_risk in ('low', 'medium', 'high')),
  mode text not null check (mode in ('auto', 'approval_required', 'suggest_only')),
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected', 'auto_executed', 'failed')),
  reviewed_by uuid references profiles(id),
  reviewed_at timestamptz,
  created_at timestamptz default now()
);

-- Agent executions (when a suggestion is actually acted upon)
create table agent_executions (
  id uuid primary key default uuid_generate_v4(),
  org_id uuid references organizations(id) on delete cascade not null,
  suggestion_id uuid references agent_suggestions(id) on delete cascade not null,
  executed_at timestamptz default now(),
  executed_by text not null,
  result jsonb default '{}',
  success boolean not null,
  output_log text
);

-- Permission policies (what AI can do, per org/asset/tag)
create table permission_policies (
  id uuid primary key default uuid_generate_v4(),
  org_id uuid references organizations(id) on delete cascade not null,
  name text not null,
  description text,
  scope text not null check (scope in ('org', 'asset', 'tag')),
  scope_value text,
  rules jsonb not null default '[]',
  is_active boolean default true,
  created_at timestamptz default now()
);

-- Integrations (external tools config)
create table integrations (
  id uuid primary key default uuid_generate_v4(),
  org_id uuid references organizations(id) on delete cascade not null,
  type text not null,
  config jsonb default '{}',
  enabled boolean default true,
  created_at timestamptz default now()
);

-- Audit log
create table audit_log (
  id uuid primary key default uuid_generate_v4(),
  org_id uuid references organizations(id) on delete cascade not null,
  actor_type text not null check (actor_type in ('user', 'agent', 'system')),
  actor_id text not null,
  action text not null,
  entity_type text,
  entity_id text,
  metadata jsonb default '{}',
  created_at timestamptz default now()
);

-- Notifications
create table notifications (
  id uuid primary key default uuid_generate_v4(),
  org_id uuid references organizations(id) on delete cascade not null,
  user_id uuid references profiles(id) on delete cascade not null,
  type text not null,
  title text not null,
  body text,
  read boolean default false,
  metadata jsonb default '{}',
  created_at timestamptz default now()
);

-- RLS policies (all tables isolated by org_id)
alter table organizations enable row level security;
alter table profiles enable row level security;
alter table assets enable row level security;
alter table scan_schedules enable row level security;
alter table scans enable row level security;
alter table findings enable row level security;
alter table agent_runs enable row level security;
alter table agent_suggestions enable row level security;
alter table agent_executions enable row level security;
alter table permission_policies enable row level security;
alter table integrations enable row level security;
alter table audit_log enable row level security;
alter table notifications enable row level security;

-- Helper function: get current user's org_id
create or replace function current_org_id()
returns uuid as $$
  select org_id from profiles where id = auth.uid()
$$ language sql security definer;

-- Apply RLS on key tables (repeat pattern for all)
create policy "org_isolation" on assets
  using (org_id = current_org_id());

create policy "org_isolation" on findings
  using (org_id = current_org_id());

create policy "org_isolation" on scans
  using (org_id = current_org_id());

create policy "org_isolation" on agent_suggestions
  using (org_id = current_org_id());

create policy "org_isolation" on permission_policies
  using (org_id = current_org_id());

create policy "own_notifications" on notifications
  using (user_id = auth.uid());
```

---

## Agent Architecture

### Core principle: structured state, no conversation history

Agents do NOT pass full message histories. Each agent receives a typed slice of the `ScanState` object, calls the LLM with a focused system prompt + that slice as JSON, and returns a typed output. This is the primary token optimization strategy.

### `backend/agents/state.py`

Define these Pydantic models as the shared state object passed between agents:

```python
from pydantic import BaseModel
from typing import Optional
from datetime import datetime


class AssetInfo(BaseModel):
    id: str
    name: str
    host: str
    port: Optional[int]
    type: str
    is_internal: bool
    tags: list[str]


class RawFinding(BaseModel):
    tool: str  # nuclei / nmap / zap
    template_id: Optional[str]
    name: str
    host: str
    severity: str
    raw: dict


class AnalyzedFinding(BaseModel):
    id: str  # deterministic fingerprint
    title: str
    description: str
    severity: str  # critical/high/medium/low/info
    cvss_score: Optional[float]
    cve_ids: list[str]
    confidence: float  # 0-1, analyst's confidence this is real
    rationale: str  # why the analyst classified it this way


class EnrichedFinding(BaseModel):
    finding_id: str
    threat_context: str  # short paragraph from threat intel agent
    exploitability: str  # none/low/medium/high/active
    public_exploits_exist: bool
    references: list[str]


class RemediationSuggestion(BaseModel):
    finding_id: str
    action_type: str
    title: str
    description: str
    command_or_patch: Optional[str]
    estimated_risk: str  # low/medium/high — risk of the fix itself
    confidence: float


class RiskDecision(BaseModel):
    suggestion_id: str
    mode: str  # auto / approval_required / suggest_only
    reason: str  # why this mode was chosen


class ScanReport(BaseModel):
    summary: str
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    top_priorities: list[str]  # finding IDs ordered by priority
    recommended_next_steps: str


class ScanState(BaseModel):
    scan_id: str
    org_id: str
    asset: AssetInfo
    permission_rules: list[dict]  # loaded from permission_policies table
    raw_findings: list[RawFinding] = []
    analyzed_findings: list[AnalyzedFinding] = []
    enriched_findings: list[EnrichedFinding] = []
    remediation_suggestions: list[RemediationSuggestion] = []
    risk_decisions: list[RiskDecision] = []
    report: Optional[ScanReport] = None
    errors: list[str] = []
```

### `backend/agents/base.py`

```python
import anthropic
from abc import ABC, abstractmethod
from backend.agents.state import ScanState

client = anthropic.Anthropic()  # reads ANTHROPIC_API_KEY from env

class BaseAgent(ABC):
    model = "claude-opus-4-5"
    agent_type: str = ""

    def call_llm(self, system: str, user_content: str, max_tokens: int = 1024) -> tuple[str, int]:
        """
        Call Claude with structured system + user content.
        Returns (response_text, tokens_used).
        Never passes conversation history.
        """
        response = client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user_content}]
        )
        text = response.content[0].text
        tokens = response.usage.input_tokens + response.usage.output_tokens
        return text, tokens

    @abstractmethod
    def run(self, state: ScanState) -> ScanState:
        pass
```

### `backend/agents/pipeline.py`

```python
from backend.agents.state import ScanState
from backend.agents.recon_agent import ReconAgent
from backend.agents.analyst_agent import AnalystAgent
from backend.agents.threat_intel_agent import ThreatIntelAgent
from backend.agents.remediation_agent import RemediationAgent
from backend.agents.risk_manager_agent import RiskManagerAgent
from backend.agents.reporter_agent import ReporterAgent
from backend.core.supabase_client import supabase
import json


def run_pipeline(state: ScanState) -> ScanState:
    """
    Sequential agent pipeline. Each agent mutates and returns state.
    Errors in one agent are logged and pipeline continues.
    """
    agents = [
        ReconAgent(),
        AnalystAgent(),
        ThreatIntelAgent(),
        RemediationAgent(),
        RiskManagerAgent(),
        ReporterAgent(),
    ]

    for agent in agents:
        try:
            state = agent.run(state)
            _log_agent_run(state, agent.agent_type, success=True)
        except Exception as e:
            state.errors.append(f"{agent.agent_type}: {str(e)}")
            _log_agent_run(state, agent.agent_type, success=False, error=str(e))

    return state


def _log_agent_run(state: ScanState, agent_type: str, success: bool, error: str = None):
    supabase.table("agent_runs").insert({
        "org_id": state.org_id,
        "scan_id": state.scan_id,
        "agent_type": agent_type,
        "status": "completed" if success else "failed",
        "error_message": error,
    }).execute()
```

### Each agent — implementation notes

**`recon_agent.py`** — does NOT call LLM. Calls scanner subprocesses (Nuclei, Nmap), parses raw output, populates `state.raw_findings`. Uses `ScannerBase` wrappers.

**`analyst_agent.py`** — receives `state.raw_findings` as JSON. System prompt: "You are a vulnerability analyst. Classify each finding, assign severity, generate a fingerprint, and assess confidence. Respond ONLY with a JSON array matching the AnalyzedFinding schema." Parse response as `list[AnalyzedFinding]`. Store in `state.analyzed_findings`.

**`threat_intel_agent.py`** — receives only `state.analyzed_findings` (not raw findings). System prompt focused on CVE enrichment and exploitability context. Populates `state.enriched_findings`.

**`remediation_agent.py`** — receives `analyzed_findings` + `enriched_findings`. For each finding generates a `RemediationSuggestion`. Include the asset context (is_internal, tags) in prompt so suggestions are appropriate. Populates `state.remediation_suggestions`.

**`risk_manager_agent.py`** — receives `state.remediation_suggestions` + `state.permission_rules`. Decides mode (auto/approval_required/suggest_only) for each suggestion by checking permission_rules. This agent is mostly logic-driven with LLM as fallback for ambiguous cases. Populates `state.risk_decisions`.

**`reporter_agent.py`** — receives counts and top findings only (not full raw data). Generates `ScanReport`. This is the only agent output shown directly on the dashboard summary.

---

## Backend API Endpoints

Implement in FastAPI. All routes require a valid Supabase JWT (verify with `supabase.auth.get_user(token)`). Extract `org_id` from the user's profile.

```
GET    /api/assets              - list assets for org
POST   /api/assets              - create asset
PATCH  /api/assets/{id}         - update asset
DELETE /api/assets/{id}         - delete asset

GET    /api/scans                - list scans (paginated)
POST   /api/scans                - trigger manual scan {asset_id, tools[]}
GET    /api/scans/{id}           - scan detail + agent run timeline

GET    /api/findings             - list findings (filter by severity, status, asset)
PATCH  /api/findings/{id}        - update status (false_positive, accepted_risk, etc.)

GET    /api/findings/{id}/suggestions  - list agent suggestions for a finding
POST   /api/suggestions/{id}/approve   - approve a suggestion (sets mode to execute)
POST   /api/suggestions/{id}/reject    - reject a suggestion

GET    /api/permissions          - list permission policies
POST   /api/permissions          - create policy
PATCH  /api/permissions/{id}     - update policy
DELETE /api/permissions/{id}     - delete policy

GET    /api/schedules            - list scan schedules
POST   /api/schedules            - create schedule
PATCH  /api/schedules/{id}       - update schedule

GET    /api/notifications        - list unread notifications for user
PATCH  /api/notifications/{id}/read

GET    /api/dashboard/stats      - {total_assets, open_findings_by_severity, recent_scans, pending_suggestions}
```

---

## Frontend Pages

### `/login`
Supabase Auth UI. Email/password. After login, redirect to `/dashboard`.

### `/dashboard`
- Stats bar: total assets, open critical findings, pending AI suggestions, last scan time
- Recent findings list (last 10, sortable by severity)
- Agent activity feed (Realtime, subscribed to `agent_runs` table for current org)
- Scan status widget (running scans with progress indicator)

### `/assets`
- Table of all assets (name, host, type, internal/external badge, tags, last scan, active findings count)
- "Add Asset" button → modal form (host, port, type, is_internal, tags)
- Per row: "Scan now" button, edit, delete

### `/scans`
- List of scans with status badges, asset name, duration, finding counts
- Click scan → detail page with agent run timeline (which agent ran, tokens used, output summary)

### `/findings`
- Filterable table: severity, status, asset, date range
- Click finding → detail page with:
  - Full description + CVE links
  - Threat intel context
  - Agent suggestions list (each with action, confidence, estimated_risk, mode badge, approve/reject buttons)
  - History timeline (first seen, last seen, status changes)

### `/permissions`
This is the key page. Layout:

- Left sidebar: list of policies (scoped to org / specific asset / tag)
- Right panel: policy editor

Policy editor shows a rule builder:
- Action type dropdown (update_library / apply_firewall_rule / restart_service / block_ip / patch_config / ...)
- Mode selector: `suggest_only` | `approval_required` | `auto`
- Conditions (optional): asset tags, severity max, is_internal only
- Save / Delete buttons

Render current policies as human-readable cards: "For assets tagged `non-critical`: update_library → AUTO | apply_firewall_rule → APPROVAL REQUIRED"

### `/settings`
- Organization name
- Integrations (Shodan API key, Nuclei templates path)
- Scan schedule management

---

## `backend/scanners/nuclei_scanner.py`

```python
import subprocess
import json
from backend.agents.state import RawFinding


class NucleiScanner:
    def scan(self, host: str, port: int = None) -> list[RawFinding]:
        target = f"{host}:{port}" if port else host
        cmd = [
            "nuclei", "-target", target,
            "-json-export", "/tmp/nuclei_out.json",
            "-severity", "critical,high,medium,low",
            "-silent"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        findings = []
        try:
            with open("/tmp/nuclei_out.json") as f:
                for line in f:
                    data = json.loads(line)
                    findings.append(RawFinding(
                        tool="nuclei",
                        template_id=data.get("template-id"),
                        name=data.get("info", {}).get("name", ""),
                        host=data.get("host", ""),
                        severity=data.get("info", {}).get("severity", "info"),
                        raw=data
                    ))
        except FileNotFoundError:
            pass

        return findings
```

Implement `nmap_scanner.py` similarly using `python-nmap` or subprocess with `-oJ` JSON output.

---

## Permission Resolution Logic

In `risk_manager_agent.py`, implement this resolution logic before calling the LLM:

```python
def resolve_mode(suggestion: RemediationSuggestion, asset: AssetInfo, rules: list[dict]) -> str:
    """
    Checks permission_policies rules in order.
    Returns: 'auto' | 'approval_required' | 'suggest_only'
    Default if no rule matches: 'suggest_only'
    """
    for rule in rules:
        action_match = rule.get("action") == suggestion.action_type or rule.get("action") == "*"
        if not action_match:
            continue

        conditions = rule.get("conditions", {})
        if "asset_tags" in conditions:
            if not any(tag in asset.tags for tag in conditions["asset_tags"]):
                continue
        if "is_internal_only" in conditions:
            if conditions["is_internal_only"] and not asset.is_internal:
                continue
        if "severity_max" in conditions:
            # Only allow auto on findings at or below this severity
            severity_order = ["info", "low", "medium", "high", "critical"]
            # implement comparison
            pass

        return rule.get("mode", "suggest_only")

    return "suggest_only"
```

---

## PWA Configuration

### `frontend/public/manifest.json`

```json
{
  "name": "DefendingAgents",
  "short_name": "DefendingAgents",
  "description": "AI-native blue team security platform",
  "start_url": "/",
  "display": "standalone",
  "background_color": "#0f1117",
  "theme_color": "#0f1117",
  "icons": [
    { "src": "/icon-192.png", "sizes": "192x192", "type": "image/png" },
    { "src": "/icon-512.png", "sizes": "512x512", "type": "image/png" }
  ]
}
```

---

## Environment Variables — `.env.example`

```
# Supabase
SUPABASE_URL=https://xxxx.supabase.co
SUPABASE_ANON_KEY=
SUPABASE_SERVICE_ROLE_KEY=

# Anthropic
ANTHROPIC_API_KEY=

# App
ENVIRONMENT=development
SECRET_KEY=changeme

# Optional integrations
SHODAN_API_KEY=
```

---

## `docker-compose.yml`

```yaml
version: "3.9"
services:
  backend:
    build: ./backend
    ports:
      - "8000:8000"
    env_file: .env
    volumes:
      - ./backend:/app
    command: uvicorn main:app --reload --host 0.0.0.0 --port 8000

  frontend:
    build: ./frontend
    ports:
      - "5173:5173"
    volumes:
      - ./frontend:/app
      - /app/node_modules
    command: npm run dev -- --host
```

---

## `backend/requirements.txt`

```
fastapi==0.115.0
uvicorn[standard]==0.30.0
anthropic==0.40.0
supabase==2.9.0
pydantic==2.9.0
python-dotenv==1.0.1
apscheduler==3.10.4
python-nmap==0.7.1
httpx==0.27.0
```

---

## `frontend/package.json` — key dependencies

```json
{
  "dependencies": {
    "react": "^18.3.1",
    "react-dom": "^18.3.1",
    "react-router-dom": "^6.27.0",
    "@supabase/supabase-js": "^2.46.0",
    "@supabase/auth-ui-react": "^0.4.7",
    "lucide-react": "^0.453.0",
    "recharts": "^2.13.0",
    "date-fns": "^4.1.0",
    "clsx": "^2.1.1",
    "tailwind-merge": "^2.5.4"
  },
  "devDependencies": {
    "@vitejs/plugin-react": "^4.3.3",
    "tailwindcss": "^3.4.14",
    "typescript": "^5.6.3",
    "vite": "^5.4.10",
    "vite-plugin-pwa": "^0.21.0"
  }
}
```

---

## Design System

Dark theme. Background `#0f1117`. Surface cards `#161b22`. Borders `#30363d` (GitHub dark palette). Accent color `#58a6ff` (blue). Severity colors:

- Critical: `#ff4444`
- High: `#ff8c00`
- Medium: `#ffd700`
- Low: `#58a6ff`
- Info: `#8b949e`

Agent mode badges:
- `auto` → green `#3fb950`
- `approval_required` → yellow `#d29922`
- `suggest_only` → gray `#8b949e`

---

## Build Order

Execute in this order:

1. Create full directory structure
2. Write `supabase/migrations/001_initial.sql`
3. Write `backend/core/config.py` and `supabase_client.py`
4. Write `backend/agents/state.py` (all Pydantic models)
5. Write `backend/agents/base.py`
6. Write all 6 agents
7. Write `backend/agents/pipeline.py`
8. Write scanner wrappers
9. Write all FastAPI endpoints
10. Write `backend/main.py` (mounts router, CORS, auth middleware)
11. Write all frontend pages and components
12. Write PWA config (manifest.json, sw.js, vite-plugin-pwa config)
13. Write docker-compose.yml, .env.example, README.md

---

## README.md — include these sections

- What it is (2 sentences)
- Architecture diagram (ASCII)
- Agent pipeline description
- Quick start (docker-compose up)
- How to add scan targets
- How to configure permission policies
- How to run the agent pipeline manually via API
- Environment variables reference

---

## Notes

- Agents must ALWAYS output valid JSON matching their Pydantic schema. Add retry logic (max 2 retries) if JSON parse fails.
- The `fingerprint` field on findings must be deterministic: `sha256(f"{asset_id}:{tool}:{template_id or name}")` so rescans deduplicate automatically.
- The ReconAgent is the ONLY agent that runs subprocess tools. No other agent touches the filesystem or network directly.
- RiskManagerAgent resolves mode via `resolve_mode()` logic first. LLM is only called for ambiguous cases where no matching rule exists.
- All agent suggestions default to `suggest_only` unless a permission_policy explicitly grants `auto` or `approval_required`.
- Supabase Realtime: frontend subscribes to `agent_runs` and `findings` channels filtered by `org_id`. No polling.
