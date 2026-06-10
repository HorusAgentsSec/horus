-- Programmatic API keys: long-lived credentials for service integrations and exporters.
-- Once created, the secret is shown to the user ONE time; we store only the hashed value.
-- Prefix (first 16 chars) and last_used_at enable key rotation UI and audit trails.
create table if not exists api_keys (
  id          uuid primary key default gen_random_uuid(),
  org_id      uuid references organizations(id) on delete cascade not null,
  name        text not null,
  key_hash    text not null, -- sha256 hex of the full key
  key_prefix  text not null, -- hrs_<first 8 chars after hrs_> for display
  role        text not null default 'analyst', -- analyst | admin
  created_by  uuid references profiles(id) on delete set null,
  created_at  timestamptz not null default now(),
  last_used_at timestamptz,
  revoked_at  timestamptz,
  unique(org_id, name)
);

create index if not exists idx_api_keys_org
  on api_keys(org_id) where revoked_at is null;

create index if not exists idx_api_keys_hash
  on api_keys(key_hash) where revoked_at is null;

alter table api_keys enable row level security;
create policy "org_isolation" on api_keys
  using (org_id = current_org_id());
