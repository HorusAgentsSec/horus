-- Fix privilege escalation on profiles.
--
-- The previous `org_isolation` policy (002_team.sql) was FOR ALL with no WITH CHECK,
-- so any authenticated org member could UPDATE any profile row in their org — including
-- their own `role` (viewer -> admin) or other members' roles. Role is a privilege
-- boundary and must not be self-service writable.
--
-- Every legitimate profile write — invite (upsert), role change, removal, and the
-- must_change_password flag clear — goes through the service-role client, which bypasses
-- RLS. So through the user-scoped (authed) client, members only ever need to READ profiles
-- (team list, own role/org lookup). We therefore replace the all-verbs policy with a
-- read-only one. current_org_id() is SECURITY DEFINER, so it keeps working under this policy.

drop policy "org_isolation" on profiles;

create policy "org_read" on profiles
  for select
  using (org_id = current_org_id());
