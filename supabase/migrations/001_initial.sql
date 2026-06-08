-- gen_random_uuid() está disponible nativamente en Postgres 13+ (Supabase lo incluye)

-- Organizations
create table organizations (
  id uuid primary key default gen_random_uuid(),
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
  id uuid primary key default gen_random_uuid(),
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
  id uuid primary key default gen_random_uuid(),
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
  id uuid primary key default gen_random_uuid(),
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
  id uuid primary key default gen_random_uuid(),
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
  id uuid primary key default gen_random_uuid(),
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
  id uuid primary key default gen_random_uuid(),
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
  id uuid primary key default gen_random_uuid(),
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
  id uuid primary key default gen_random_uuid(),
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
  id uuid primary key default gen_random_uuid(),
  org_id uuid references organizations(id) on delete cascade not null,
  type text not null,
  config jsonb default '{}',
  enabled boolean default true,
  created_at timestamptz default now()
);

-- Audit log
create table audit_log (
  id uuid primary key default gen_random_uuid(),
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
  id uuid primary key default gen_random_uuid(),
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

-- Apply RLS on key tables
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
