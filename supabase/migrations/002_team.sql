-- Invitations (pending users not yet signed up)
create table invitations (
  id uuid primary key default gen_random_uuid(),
  org_id uuid references organizations(id) on delete cascade not null,
  email text not null,
  role text not null default 'analyst' check (role in ('admin', 'analyst', 'viewer')),
  invited_by uuid references profiles(id) on delete set null,
  token text unique not null default replace(gen_random_uuid()::text, '-', '') || replace(gen_random_uuid()::text, '-', ''),
  accepted boolean default false,
  expires_at timestamptz not null default now() + interval '7 days',
  created_at timestamptz default now(),
  unique(org_id, email)
);

alter table invitations enable row level security;

create policy "org_isolation" on invitations
  using (org_id = current_org_id());

-- Allow admins to see all profiles in their org (needed for team list)
create policy "org_isolation" on profiles
  using (org_id = current_org_id());
