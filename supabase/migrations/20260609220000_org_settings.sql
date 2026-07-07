-- Per-organization settings: secrets/config the user manages from the Settings page,
-- as opposed to deploy-time backend env vars. One row per org. RLS-scoped like every
-- other user-facing table so the per-request authed client reads/writes only its own org.
create table if not exists org_settings (
  org_id         uuid primary key references organizations(id) on delete cascade,
  shodan_api_key text,
  updated_at     timestamptz not null default now()
);

alter table org_settings enable row level security;
create policy "org_isolation" on org_settings
  using (org_id = current_org_id());
