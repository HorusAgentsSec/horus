-- Asset auto-discovery sources.
--
-- A discovery source is a domain whose attack surface we map passively (Certificate
-- Transparency logs + DNS) to find subdomains/hosts and auto-create them as assets.
-- Optionally scheduled (cron_expression) so the surface is re-discovered over time —
-- the whole point is "configure once, keep finding new exposure on its own".
--
-- Discovery is passive: it never scans. Scanning stays a separate, guarded step.

create table discovery_sources (
  id                 uuid primary key default gen_random_uuid(),
  org_id             uuid references organizations(id) on delete cascade not null,
  domain             text not null,
  cron_expression    text,                       -- null = manual-only; set = scheduled
  auto_create_assets boolean not null default true,
  enabled            boolean not null default true,
  last_run_at        timestamptz,
  last_found_count   integer,
  created_at         timestamptz default now()
);

alter table discovery_sources enable row level security;

-- Org-isolated (USING also gates INSERT: new row's org_id must equal current_org_id()).
create policy "org_isolation" on discovery_sources
  using (org_id = current_org_id());
