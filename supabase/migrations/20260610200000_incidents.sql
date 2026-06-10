-- Case Management: group related findings into incidents with an owner + SLA.
--
-- A SOC needs more than a flat list of findings. Incidents cluster related findings
-- under a single owner, track a status lifecycle and SLA deadline, and capture an
-- activity log (notes). RLS keeps everything org-scoped via current_org_id(), the
-- same helper every other tenant table uses.

-- ── Incidents ────────────────────────────────────────────────────────────────
create table incidents (
  id           uuid primary key default gen_random_uuid(),
  org_id       uuid not null references organizations(id) on delete cascade,
  title        text not null,
  description  text,
  status       text not null default 'open'
               check (status in ('open', 'in_progress', 'resolved', 'closed')),
  severity     text not null default 'medium'
               check (severity in ('critical', 'high', 'medium', 'low')),
  assignee_id  uuid references auth.users(id) on delete set null,
  sla_deadline timestamptz,
  created_by   uuid references auth.users(id) on delete set null,
  created_at   timestamptz not null default now(),
  closed_at    timestamptz,
  updated_at   timestamptz not null default now()
);

-- N:M link between incidents and the findings they cluster.
create table incident_findings (
  incident_id uuid not null references incidents(id) on delete cascade,
  finding_id  uuid not null references findings(id) on delete cascade,
  added_at    timestamptz not null default now(),
  primary key (incident_id, finding_id)
);

-- Append-only activity log per incident.
create table incident_notes (
  id          uuid primary key default gen_random_uuid(),
  incident_id uuid not null references incidents(id) on delete cascade,
  author_id   uuid not null references auth.users(id) on delete cascade,
  body        text not null,
  created_at  timestamptz not null default now()
);

-- ── RLS (org-scoped via current_org_id(), the project-wide convention) ────────
alter table incidents enable row level security;
alter table incident_findings enable row level security;
alter table incident_notes enable row level security;

create policy "org_isolation" on incidents
  using (org_id = current_org_id());

-- Child tables have no org_id of their own; they inherit org scope through their
-- parent incident, which is itself filtered by current_org_id().
create policy "org_isolation" on incident_findings
  using (
    exists (
      select 1 from incidents i
      where i.id = incident_findings.incident_id
        and i.org_id = current_org_id()
    )
  );

create policy "org_isolation" on incident_notes
  using (
    exists (
      select 1 from incidents i
      where i.id = incident_notes.incident_id
        and i.org_id = current_org_id()
    )
  );

-- ── Indexes ──────────────────────────────────────────────────────────────────
create index incidents_org_idx on incidents (org_id, created_at desc);
create index incidents_status_idx on incidents (org_id, status);
create index incidents_assignee_idx on incidents (assignee_id);
create index incident_findings_finding_idx on incident_findings (finding_id);
create index incident_notes_incident_idx on incident_notes (incident_id, created_at);

-- ── updated_at maintenance ───────────────────────────────────────────────────
create or replace function update_incident_timestamp()
returns trigger language plpgsql as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

create trigger incidents_updated_at
  before update on incidents
  for each row execute function update_incident_timestamp();
