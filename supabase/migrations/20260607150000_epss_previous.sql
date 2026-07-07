-- EPSS spike detection for Watchtower.
--
-- The KEV signal answers "is this exploited TODAY"; EPSS answers "how likely is exploitation
-- soon". A sharp jump in a CVE's EPSS score is an early warning — often the days before a CVE
-- enters KEV. To detect a jump we need yesterday's value, but the daily sync overwrites the
-- score. So we keep the prior value in epss_previous and snapshot it (current -> previous) right
-- before each sync overwrites the current score. snapshot_epss() does that column-to-column copy
-- (which PostgREST can't express), called from cve_intel.run_sync.

alter table cve_intel add column if not exists epss_previous double precision;

-- statement_timeout is raised on the function itself: the bulk copy over ~340k rows exceeds the
-- PostgREST API role's short default timeout (~8s), so without this the daily RPC call would always
-- time out (57014) and spike detection would never get a baseline.
create or replace function snapshot_epss() returns void
language sql
security definer
set search_path = public
set statement_timeout = '240s'
as $$
  update cve_intel set epss_previous = epss_score where epss_score is not null;
$$;
