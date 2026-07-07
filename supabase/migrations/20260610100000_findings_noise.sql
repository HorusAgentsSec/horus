-- findings.is_noise: deterministic flag for "absence of finding" noise the Analyst lets
-- through ("No DOM-based XSS found on port 8080", "not vulnerable to CVE-…", nmap script
-- errors). GET /api/findings hides these by default (include_noise=true to see them);
-- backend/core/noise.py applies the same patterns to new findings at persist time.
alter table findings add column if not exists is_noise boolean not null default false;

-- The default listing always filters is_noise = false per org.
create index if not exists idx_findings_org_not_noise on findings(org_id) where is_noise = false;

-- Backfill existing rows. Keep these patterns in sync with backend/core/noise.py.
update findings set is_noise = true
where title ~* '^\s*no\s+.*\m(found|detected|identified|observed)\M'
   or title ~* '\mnot\s+vulnerable\M'
   or title ~* '\m(returned|reported|revealed)\s+no\s+(finding|vulnerabilit|issue|result)'
   or title ~* '\m(couldn''?t|could\s+not|unable\s+to)\s+(find|detect|identify)\M'
   or title ~* '\mnone\s+(found|detected|identified)\M'
   or (severity = 'info' and (
        title ~* '\mscript\s+(error|execution\s+failed)\M'
     or title ~* '\minconclusive\M'
     or title ~* '\(negative\)'
   ));
