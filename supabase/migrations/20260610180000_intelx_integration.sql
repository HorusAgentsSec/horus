-- Add IntelligenceX API key support to org_settings
alter table org_settings
  add column if not exists intelx_api_key text;
