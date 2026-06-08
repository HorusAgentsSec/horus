-- CPE -> CVE lookup cache.
--
-- On-demand correlation: when a scan detects a service (e.g. nginx 1.18.0) we ask
-- NVD which CVEs apply to that product+version (NVD does the version-range matching
-- server-side, which is correct and maintained). The answer is cached here so repeat
-- scans of the same software don't re-hit NVD (rate-limited) and work offline once warm.
--
-- The CVE severity/exploit data for each id lives in cve_intel (KEV/EPSS/CVSS); this
-- table only maps "this product:version" -> "these CVE ids". Global reference data:
-- authenticated read, service-role-only writes (the correlation job bypasses RLS).

create table cpe_lookup_cache (
  cpe_key    text primary key,                 -- normalized "vendor:product:version"
  cve_ids    text[] not null default '{}',
  fetched_at timestamptz not null default now()
);

alter table cpe_lookup_cache enable row level security;

create policy "authenticated_read" on cpe_lookup_cache
  for select
  to authenticated
  using (true);
