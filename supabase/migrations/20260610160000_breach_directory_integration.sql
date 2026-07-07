-- Add BreachDirectory API key support to org_settings
alter table org_settings
  add column if not exists breach_directory_api_key text;

-- Add employee_karma_enabled if missing (safe to re-run)
alter table org_settings
  add column if not exists employee_karma_enabled boolean default false;
