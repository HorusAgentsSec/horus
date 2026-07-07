-- Horus Iris: registered Unix agents and the raw events they stream.
--
-- Iris daemons run on servers, detect suspicious activity (file changes,
-- new listeners, auth events, log anomalies…), and POST batches of events
-- to /api/iris/events. Events queue in iris_events until the batch-process
-- endpoint converts them to RawFindings and fires them through the AI pipeline.
--
-- Auth: each agent has its own API key (prefix irs_, stored as SHA-256),
-- completely independent of user API keys (hrs_).

-- ── Registered Iris agents ────────────────────────────────────────────────────
create table iris_agents (
  id            uuid primary key default gen_random_uuid(),
  org_id        uuid not null references organizations(id) on delete cascade,
  name          text not null,                          -- human label given by the user
  hostname      text,                                   -- auto-sent by the daemon
  platform      text,                                   -- 'linux' | 'darwin'
  ip            text,                                   -- last known IP
  api_key_hash  text not null,                          -- SHA-256 of irs_<token>
  key_prefix    text not null,                          -- first 12 chars for display
  asset_id      uuid references assets(id) on delete set null,  -- optional link to an asset
  last_seen_at  timestamptz,
  status        text not null default 'offline'
                check (status in ('online', 'offline', 'degraded')),
  config        jsonb not null default '{}',            -- watch_paths, ignore_patterns, interval_seconds
  created_at    timestamptz not null default now(),
  created_by    uuid references auth.users(id) on delete set null
);

-- ── Raw events streamed by Iris daemons ───────────────────────────────────────
create table iris_events (
  id          uuid primary key default gen_random_uuid(),
  agent_id    uuid not null references iris_agents(id) on delete cascade,
  org_id      uuid not null references organizations(id) on delete cascade,
  event_type  text not null
              check (event_type in (
                'file_change', 'new_process', 'new_listener',
                'new_connection', 'auth_event', 'log_anomaly'
              )),
  severity    text not null default 'info'
              check (severity in ('info', 'low', 'medium', 'high', 'critical')),
  title       text not null,
  payload     jsonb not null,                           -- event-specific data
  received_at timestamptz not null default now(),
  processed   boolean not null default false,
  scan_id     uuid references scans(id) on delete set null  -- filled when batched
);

-- ── Indexes ──────────────────────────────────────────────────────────────────
create index iris_agents_org_idx   on iris_agents (org_id);
create index iris_events_agent_idx on iris_events (agent_id, processed);
create index iris_events_org_idx   on iris_events (org_id, received_at desc);

-- ── RLS ──────────────────────────────────────────────────────────────────────
alter table iris_agents enable row level security;
alter table iris_events  enable row level security;

create policy "org_isolation" on iris_agents
  using (org_id = current_org_id());

create policy "org_isolation" on iris_events
  using (org_id = current_org_id());
