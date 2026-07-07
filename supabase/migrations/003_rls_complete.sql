-- Complete RLS coverage so the per-request authed client works on every
-- user-facing table. Tables with RLS enabled but no policy deny all access.
-- The existing org_isolation policies are FOR ALL with USING copied to WITH CHECK,
-- so they also gate INSERTs (new row's org_id must equal current_org_id()).

create policy "org_isolation" on scan_schedules
  using (org_id = current_org_id());

create policy "org_isolation" on agent_runs
  using (org_id = current_org_id());

create policy "org_isolation" on agent_executions
  using (org_id = current_org_id());

create policy "org_isolation" on integrations
  using (org_id = current_org_id());

create policy "org_isolation" on audit_log
  using (org_id = current_org_id());

-- Users can read their own organization row
create policy "own_org" on organizations
  using (id = current_org_id());
