-- Persist the ReporterAgent's executive summary on the scan.
--
-- The pipeline already generates a per-scan report (summary, severity counts, SSVC-ordered top
-- priorities, recommended next steps) but it was being thrown away. Storing it lets the scan detail
-- view show the written verdict — the "what happened and what to do" the user would otherwise have
-- to assemble by hand. jsonb so the shape can evolve without a migration.

alter table scans add column if not exists report jsonb;
