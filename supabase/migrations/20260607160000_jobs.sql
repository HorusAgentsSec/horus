-- Jobs — unified execution history for all background work.
--
-- The platform runs a lot on its own: scheduled scans, asset discovery, the daily CVE/KEV/EPSS
-- sync, Watchtower, posture snapshots, the monthly board report. Until now each ran silently with
-- no durable record of "did it run, when, did it succeed". This table is the operations log: one
-- row per execution, so the UI can show a history and surface failures — the visibility that makes
-- "configure once and trust it" actually trustworthy.
--
-- org_id is null for system-wide jobs (the global crons); set for per-org jobs (a schedule/discovery
-- source). Writes happen through the service-role scheduler; users only read.

create table jobs (
  id           uuid primary key default gen_random_uuid(),
  org_id       uuid references organizations(id) on delete cascade,  -- null = system-wide job
  job_type     text not null,            -- scan_schedule | discovery | cve_sync | watchtower | posture_snapshot | posture_report
  ref_id       uuid,                      -- the schedule / discovery source it ran for (null for global crons)
  trigger      text not null default 'cron',                          -- cron | manual
  status       text not null default 'running' check (status in ('running', 'completed', 'failed')),
  detail       jsonb not null default '{}',  -- result summary (counts) or error context
  error        text,
  started_at   timestamptz not null default now(),
  finished_at  timestamptz,
  duration_ms  integer
);

create index jobs_org_idx on jobs (org_id, started_at desc);
create index jobs_type_idx on jobs (job_type, started_at desc);

alter table jobs enable row level security;

-- Members read their org's jobs; system-wide jobs (org_id null) are visible to all authed users
-- (operational transparency — the detail is just counts, never another tenant's data).
create policy "org_isolation" on jobs
  using (org_id = current_org_id() or org_id is null);
