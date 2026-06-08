-- Security posture snapshots — the executive timeline ("is our risk going down?").
--
-- A daily (and post-scan) snapshot of the org's open-risk picture: a single risk_score
-- plus the severity breakdown. The UI plots these over time so a customer can show their
-- boss the trend — the chart that justifies renewing the subscription.
--
-- risk_score is deterministic (severity-weighted count of open findings, with a bonus for
-- actively-exploited ones); lower is better. One row per (org, day) — recomputed snapshots
-- the same day upsert over the previous value.

create table posture_snapshots (
  id             uuid primary key default gen_random_uuid(),
  org_id         uuid references organizations(id) on delete cascade not null,
  snapshot_date  date not null default current_date,
  risk_score     integer not null default 0,    -- severity-weighted; lower is better
  open_findings  integer not null default 0,
  kev_active     integer not null default 0,    -- open findings under active exploitation
  critical       integer not null default 0,
  high           integer not null default 0,
  medium         integer not null default 0,
  low            integer not null default 0,
  info           integer not null default 0,
  created_at     timestamptz not null default now(),
  unique (org_id, snapshot_date)
);

create index posture_snapshots_org_idx on posture_snapshots (org_id, snapshot_date desc);

alter table posture_snapshots enable row level security;

-- Writes happen through the service-role job; users only read their org's history.
create policy "org_isolation" on posture_snapshots
  using (org_id = current_org_id());
