-- Watchtower — continuous exposure monitoring.
--
-- The recurring-value feature: a scan is a point-in-time snapshot, but threats emerge
-- every day. Watchtower persists each asset's detected software (inventory) and, daily
-- after the KEV/EPSS sync, re-correlates that inventory against CVEs that just became
-- known-exploited — WITHOUT re-scanning. When a product you already run enters CISA KEV,
-- you get alerted the same day. This turns a one-off scan into a perpetual watchtower.
--
-- Both tables are org-scoped. Writes happen through the service-role job (bypasses RLS);
-- the org_isolation policy gates user reads (and would gate authed writes, of which there
-- are none) — same pattern as discovery_sources.

-- Persistent software inventory per asset. The scan pipeline detects services
-- (product/version/port) but that data is otherwise ephemeral to a single scan; this
-- table is the durable record Watchtower re-correlates each day. One row per
-- (asset, product, version, port) — port defaults to 0 so the unique key never sees NULL
-- (NULLs are distinct in a unique constraint, which would break upsert dedup).
create table asset_inventory (
  id            uuid primary key default gen_random_uuid(),
  org_id        uuid references organizations(id) on delete cascade not null,
  asset_id      uuid references assets(id) on delete cascade not null,
  product       text not null,
  version       text not null,
  port          integer not null default 0,
  first_seen_at timestamptz not null default now(),
  last_seen_at  timestamptz not null default now(),
  unique (asset_id, product, version, port)
);

create index asset_inventory_org_idx on asset_inventory (org_id);

alter table asset_inventory enable row level security;
create policy "org_isolation" on asset_inventory
  using (org_id = current_org_id());

-- Alerts raised by Watchtower — dedup store + history for the UI timeline. One row per
-- (asset, cve): we never re-alert the same exposure. finding_id links to the findings row
-- created for the exposure (so it flows through the normal triage workflow).
create table watchtower_alerts (
  id          uuid primary key default gen_random_uuid(),
  org_id      uuid references organizations(id) on delete cascade not null,
  asset_id    uuid references assets(id) on delete cascade not null,
  cve_id      text not null,
  product     text not null,
  version     text not null,
  reason      text not null default 'kev_added',  -- why it fired (kev_added | epss_spike)
  severity    text,                                -- snapshot of severity at alert time
  finding_id  uuid references findings(id) on delete set null,
  created_at  timestamptz not null default now(),
  unique (asset_id, cve_id)
);

create index watchtower_alerts_org_idx on watchtower_alerts (org_id, created_at desc);

alter table watchtower_alerts enable row level security;
create policy "org_isolation" on watchtower_alerts
  using (org_id = current_org_id());
