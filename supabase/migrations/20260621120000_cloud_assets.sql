-- Cloud security audit (AWS): represent a cloud account as an asset so its misconfiguration
-- findings flow through the existing findings list, dashboard and SSVC prioritization unchanged.
-- Credentials reuse the `integrations` table (type = 'aws'); no new credential table needed.

alter table assets drop constraint if exists assets_type_check;
alter table assets add constraint assets_type_check
  check (type in ('web', 'ip', 'api', 'domain', 'cloud'));
