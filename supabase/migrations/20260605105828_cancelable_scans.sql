alter table scans
  add column if not exists triggered_by_user_id uuid references profiles(id) on delete set null;

alter table scans
  drop constraint if exists scans_status_check;

alter table scans
  add constraint scans_status_check
  check (status in ('pending', 'running', 'completed', 'failed', 'canceled'));
