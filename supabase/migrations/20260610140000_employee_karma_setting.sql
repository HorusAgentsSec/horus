-- Add employee_karma_enabled flag to org_settings table
-- Default to FALSE for EU GDPR compliance (Art. 88 — can't score employees automatically)
alter table org_settings
add column employee_karma_enabled boolean not null default false;

comment on column org_settings.employee_karma_enabled is
  'When true, endpoints return employee.karma_score and phishing campaign results include karma penalties. When false, karma is omitted from all responses. Default false for GDPR compliance.';
