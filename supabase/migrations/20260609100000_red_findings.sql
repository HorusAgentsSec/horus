-- Red/Blue adversarial agent findings.
--
-- RedAgent persists attack-surface hypotheses here (not confirmed scanner findings).
-- BlueAgent reads open rows and writes back structured remediation guidance.
-- The status column drives the UI: open → responded → accepted/false_positive.

create table red_findings (
  id              uuid primary key default gen_random_uuid(),
  org_id          uuid not null references organizations(id) on delete cascade,
  asset_id        uuid references assets(id) on delete set null,
  run_id          uuid,             -- job id of the adversarial cycle (best-effort, not FK)
  title           text not null,
  description     text not null,
  attack_scenario text,             -- attacker narrative: how this would be exploited
  severity        text not null default 'medium'
                  check (severity in ('critical','high','medium','low','info')),
  category        text not null default 'other',
                  -- dns | ssl | headers | exposed_path | subdomain | breach | exploit | network | other
  evidence        jsonb not null default '{}',   -- raw tool output that led to this finding
  status          text not null default 'open'
                  check (status in ('open','responded','accepted','false_positive')),
  blue_response   jsonb,            -- BlueAgent's structured remediation output
  created_at      timestamptz not null default now(),
  updated_at      timestamptz not null default now()
);

create index red_findings_org_idx    on red_findings (org_id, created_at desc);
create index red_findings_status_idx on red_findings (org_id, status);
create index red_findings_asset_idx  on red_findings (asset_id);

alter table red_findings enable row level security;
create policy "org_isolation" on red_findings
  using (org_id = current_org_id());

