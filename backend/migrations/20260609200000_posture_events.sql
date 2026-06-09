create table if not exists posture_events (
  id uuid primary key default gen_random_uuid(),
  org_id uuid not null references organizations(id) on delete cascade,
  event_date date not null,
  event_type text not null check (event_type in ('discovery','scan','kev_alert','watchtower_alert','manual')),
  description text not null,
  created_at timestamptz default now()
);

create index on posture_events (org_id, event_date);

alter table posture_events enable row level security;
create policy "org members read own events"
  on posture_events for select
  using (org_id = current_setting('app.current_org_id', true)::uuid);
create policy "service role full access"
  on posture_events for all
  using (current_setting('role', true) = 'service_role');
