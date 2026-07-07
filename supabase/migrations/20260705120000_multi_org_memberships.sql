-- Multi-org: a user can belong to several orgs and switch the active one.
--
-- Model
--   `memberships` is the SOURCE OF TRUTH for "which orgs a user belongs to, and with what
--   role". `profiles.org_id` / `profiles.role` keep working exactly as before, but now mean
--   the ACTIVE org/role for the session: a mirror of the currently selected membership.
--
--   Keeping the active org mirrored on profiles means current_org_id() and EVERY existing
--   RLS policy stay byte-for-byte the same: the whole isolation model still keys off
--   profiles.org_id. Switching orgs = the backend (service role) updates profiles.org_id to
--   the chosen membership.
--
-- Safety
--   A BEFORE UPDATE trigger guarantees a profile can only ever point at an org the user is a
--   member of, and forces role to mirror that membership. So even a future bug, or a direct
--   write, cannot cross-org escalate: the DB itself refuses it.

create table if not exists memberships (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references auth.users(id) on delete cascade,
  org_id     uuid not null references organizations(id) on delete cascade,
  role       text not null default 'viewer' check (role in ('admin', 'analyst', 'viewer')),
  created_at timestamptz not null default now(),
  deleted_at timestamptz,
  unique (user_id, org_id)
);

create index if not exists memberships_user_active_idx
  on memberships (user_id) where deleted_at is null;

alter table memberships enable row level security;

-- A user reads only their own memberships (this powers the org switcher). There is NO
-- insert/update/delete policy on purpose: writes are service-role only (provisioning,
-- super-admin, team management), never client-writable.
create policy "own_memberships" on memberships
  for select using (user_id = auth.uid() and deleted_at is null);

-- Backfill: every existing profile becomes a membership carrying its current org + role, and
-- that org stays the active one. Idempotent (safe to re-run).
insert into memberships (user_id, org_id, role)
  select id, org_id, role from profiles where org_id is not null
  on conflict (user_id, org_id) do nothing;

-- Security guard: a profile may only point at an org the user belongs to, and its role is
-- always forced to mirror that membership. A client cannot hand itself 'admin' by writing
-- profiles directly, and switching to a non-member org is rejected at the DB level.
create or replace function enforce_active_org_membership()
returns trigger as $$
declare
  m_role text;
begin
  if new.org_id is distinct from old.org_id then
    select role into m_role
      from memberships
      where user_id = new.id and org_id = new.org_id and deleted_at is null;
    if m_role is null then
      raise exception 'user % is not a member of org %', new.id, new.org_id;
    end if;
    new.role := m_role;
  end if;
  return new;
end;
$$ language plpgsql security definer;

drop trigger if exists trg_active_org_membership on profiles;
create trigger trg_active_org_membership
  before update on profiles
  for each row execute function enforce_active_org_membership();
