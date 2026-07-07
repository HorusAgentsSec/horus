-- Re-evaluate findings.is_noise with the stricter rule from backend/core/noise.py.
-- The original backfill (20260610100000) hid ANY title starting with "No ... found", which
-- also catches real missing controls like "No rate limiting found on login endpoint". Gate
-- that broad leading-"No" phrasing (and scanner self-noise) on severity = 'info' so genuine
-- medium/high findings stay visible. Idempotent: recomputes is_noise from the title/severity.
update findings set is_noise = (
       -- absence phrasing, any severity
       title ~* '\mnot\s+vulnerable\M'
    or title ~* '\m(returned|reported|revealed)\s+no\s+(finding|vulnerabilit|issue|result)'
    or title ~* '\m(couldn''?t|could\s+not|unable\s+to)\s+(find|detect|identify)\M'
    or title ~* '\mnone\s+(found|detected|identified)\M'
       -- info-only: leading "No ... found" + scanner self-noise
    or (severity = 'info' and (
            title ~* '^\s*no\s+.*\m(found|detected|identified|observed)\M'
         or title ~* '\mscript\s+(error|execution\s+failed)\M'
         or title ~* '\minconclusive\M'
         or title ~* '\(negative\)'
    ))
)
where title is not null;
