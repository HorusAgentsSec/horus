-- Ticketing references: one row per external ticket created from a finding (the "R" in SOAR).
-- unique(finding_id, provider) gives idempotency — re-clicking "Create Jira ticket" returns the
-- existing reference instead of opening a duplicate issue. RLS-scoped like every other table.
create table if not exists finding_tickets (
  id          uuid primary key default gen_random_uuid(),
  org_id      uuid references organizations(id) on delete cascade not null,
  finding_id  uuid references findings(id) on delete cascade not null,
  provider    text not null default 'jira',
  ticket_key  text not null,
  ticket_url  text not null,
  created_by  uuid references profiles(id) on delete set null,
  created_at  timestamptz not null default now(),
  unique(finding_id, provider)
);

create index if not exists idx_finding_tickets_org_finding
  on finding_tickets(org_id, finding_id);

alter table finding_tickets enable row level security;
create policy "org_isolation" on finding_tickets
  using (org_id = current_org_id());
