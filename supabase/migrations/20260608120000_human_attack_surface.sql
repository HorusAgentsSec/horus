-- Human Attack Surface — employees, credential breaches (HIBP), phishing campaigns.
--
-- Adds the "human layer" to the existing technical attack surface (assets/CVEs/findings).
-- Key design: karma_score on employees feeds the org risk_score alongside the technical posture;
-- breach correlations link a compromised email to the blast-radius assets that email can reach.

-- ── Employees ────────────────────────────────────────────────────────────────
create table employees (
  id            uuid primary key default gen_random_uuid(),
  org_id        uuid not null references organizations(id) on delete cascade,
  email         text not null,
  full_name     text,
  department    text,
  karma_score   integer not null default 100 check (karma_score between 0 and 100),
  hibp_checked_at timestamptz,
  created_at    timestamptz not null default now(),
  updated_at    timestamptz not null default now(),
  unique (org_id, email)
);

create index employees_org_idx on employees (org_id);
alter table employees enable row level security;
create policy "org_isolation" on employees using (org_id = current_org_id());

-- ── Credential breaches (HIBP results) ──────────────────────────────────────
create table credential_breaches (
  id            uuid primary key default gen_random_uuid(),
  org_id        uuid not null references organizations(id) on delete cascade,
  employee_id   uuid not null references employees(id) on delete cascade,
  breach_name   text not null,
  breach_date   date,
  data_classes  text[] not null default '{}',   -- e.g. ["Passwords", "Email addresses"]
  is_sensitive  boolean not null default false,
  -- correlation: which assets is this employee likely to access?
  correlated_asset_ids uuid[] not null default '{}',
  discovered_at timestamptz not null default now(),
  unique (employee_id, breach_name)
);

create index credential_breaches_org_idx on credential_breaches (org_id);
create index credential_breaches_employee_idx on credential_breaches (employee_id);
alter table credential_breaches enable row level security;
create policy "org_isolation" on credential_breaches using (org_id = current_org_id());

-- ── Phishing campaigns ───────────────────────────────────────────────────────
create table phishing_campaigns (
  id              uuid primary key default gen_random_uuid(),
  org_id          uuid not null references organizations(id) on delete cascade,
  name            text not null,
  status          text not null default 'draft' check (status in ('draft', 'scheduled', 'running', 'completed', 'cancelled')),
  objective       text not null default 'click' check (objective in ('click', 'credentials', 'report')),
  -- asset IDs used as context by the PhishingAgent (e.g. crm.bse.eu → realistic lure)
  context_asset_ids uuid[] not null default '{}',
  -- cron expression for scheduled campaigns; null = manual launch
  schedule_cron   text,
  created_by      uuid references profiles(id) on delete set null,
  launched_at     timestamptz,
  completed_at    timestamptz,
  created_at      timestamptz not null default now()
);

create index phishing_campaigns_org_idx on phishing_campaigns (org_id, created_at desc);
alter table phishing_campaigns enable row level security;
create policy "org_isolation" on phishing_campaigns using (org_id = current_org_id());

-- ── Phishing targets (one row per employee per campaign) ────────────────────
create table phishing_targets (
  id              uuid primary key default gen_random_uuid(),
  campaign_id     uuid not null references phishing_campaigns(id) on delete cascade,
  org_id          uuid not null references organizations(id) on delete cascade,
  employee_id     uuid not null references employees(id) on delete cascade,
  -- tracking token embedded in the honeypot URL (one-time, hashed on write)
  tracking_token  text unique,
  email_sent_at   timestamptz,
  link_clicked_at timestamptz,
  creds_entered_at timestamptz,
  reported_at     timestamptz,
  -- generated email content (stored so results reference what was sent)
  email_subject   text,
  email_body_html text,
  unique (campaign_id, employee_id)
);

create index phishing_targets_campaign_idx on phishing_targets (campaign_id);
create index phishing_targets_token_idx on phishing_targets (tracking_token);
alter table phishing_targets enable row level security;
create policy "org_isolation" on phishing_targets using (org_id = current_org_id());
