-- Soft-delete across the app: nothing is ever physically removed through the API.
-- Each user-managed table gets a `deleted_at` column. The org-isolation RLS policy is
-- rewritten so SELECT (and any authed read) hides soft-deleted rows automatically —
-- no SELECT in the Python code needs to change. WITH CHECK keeps the org guard but
-- drops the deleted_at clause, so the API can still write deleted_at on UPDATE.
-- Recovery is done out-of-band with the service-role key or direct SQL, which bypass RLS.
--
-- api_keys (already soft via revoked_at) and organizations (intentional hard-delete)
-- are left untouched.

-- ── deleted_at columns ───────────────────────────────────────────────────────
alter table assets               add column if not exists deleted_at timestamptz;
alter table permission_policies  add column if not exists deleted_at timestamptz;
alter table scan_schedules       add column if not exists deleted_at timestamptz;
alter table integrations         add column if not exists deleted_at timestamptz;
alter table discovery_sources    add column if not exists deleted_at timestamptz;
alter table employees            add column if not exists deleted_at timestamptz;
alter table phishing_campaigns   add column if not exists deleted_at timestamptz;
alter table phishing_templates   add column if not exists deleted_at timestamptz;
alter table red_findings         add column if not exists deleted_at timestamptz;
alter table iris_agents          add column if not exists deleted_at timestamptz;
alter table incident_findings    add column if not exists deleted_at timestamptz;
alter table notifications        add column if not exists deleted_at timestamptz;
alter table profiles             add column if not exists deleted_at timestamptz;
alter table adversarial_schedules add column if not exists deleted_at timestamptz;

-- ── org_isolation policies (FOR ALL, org_id = current_org_id()) ────────────────
alter policy "org_isolation" on assets
  using (org_id = current_org_id() and deleted_at is null) with check (org_id = current_org_id());
alter policy "org_isolation" on permission_policies
  using (org_id = current_org_id() and deleted_at is null) with check (org_id = current_org_id());
alter policy "org_isolation" on scan_schedules
  using (org_id = current_org_id() and deleted_at is null) with check (org_id = current_org_id());
alter policy "org_isolation" on integrations
  using (org_id = current_org_id() and deleted_at is null) with check (org_id = current_org_id());
alter policy "org_isolation" on discovery_sources
  using (org_id = current_org_id() and deleted_at is null) with check (org_id = current_org_id());
alter policy "org_isolation" on employees
  using (org_id = current_org_id() and deleted_at is null) with check (org_id = current_org_id());
alter policy "org_isolation" on phishing_campaigns
  using (org_id = current_org_id() and deleted_at is null) with check (org_id = current_org_id());
alter policy "org_isolation" on red_findings
  using (org_id = current_org_id() and deleted_at is null) with check (org_id = current_org_id());
alter policy "org_isolation" on iris_agents
  using (org_id = current_org_id() and deleted_at is null) with check (org_id = current_org_id());

-- ── phishing_templates (org policy + public-read policy) ───────────────────────
alter policy "org_isolation" on phishing_templates
  using (org_id = current_org_id() and deleted_at is null) with check (org_id = current_org_id());
alter policy "phishing_templates_read_public" on phishing_templates
  using (is_public = true and deleted_at is null);

-- ── notifications (own_notifications, user_id = auth.uid()) ────────────────────
alter policy "own_notifications" on notifications
  using (user_id = auth.uid() and deleted_at is null) with check (user_id = auth.uid());

-- ── profiles (org_read, FOR SELECT — no WITH CHECK) ────────────────────────────
alter policy "org_read" on profiles
  using (org_id = current_org_id() and deleted_at is null);

-- ── incident_findings (inherits org scope through parent incident) ─────────────
alter policy "org_isolation" on incident_findings
  using (
    exists (
      select 1 from incidents i
      where i.id = incident_findings.incident_id
        and i.org_id = current_org_id()
    )
    and deleted_at is null
  )
  with check (
    exists (
      select 1 from incidents i
      where i.id = incident_findings.incident_id
        and i.org_id = current_org_id()
    )
  );

-- ── adversarial_schedules (two policies: admin-manage FOR ALL + member-read FOR SELECT) ─
-- The manage policy is FOR ALL, so it also governs SELECT for admins; both need the
-- deleted_at filter to hide soft-deleted rows. WITH CHECK keeps the admin guard for writes.
alter policy "admins can manage adversarial schedules" on adversarial_schedules
  using (
    exists (
      select 1 from profiles
      where profiles.id = auth.uid()
        and profiles.org_id = adversarial_schedules.org_id
        and profiles.role = 'admin'
    )
    and deleted_at is null
  )
  with check (
    exists (
      select 1 from profiles
      where profiles.id = auth.uid()
        and profiles.org_id = adversarial_schedules.org_id
        and profiles.role = 'admin'
    )
  );
alter policy "org members can read adversarial schedules" on adversarial_schedules
  using (
    org_id = (select profiles.org_id from profiles where profiles.id = auth.uid())
    and deleted_at is null
  );
