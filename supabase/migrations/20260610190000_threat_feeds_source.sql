-- Add source column to findings for tracking the intelligence feed source
-- (threatfox, urlhaus, ransomware, watchtower, scan, etc.)
alter table findings add column if not exists source text;
