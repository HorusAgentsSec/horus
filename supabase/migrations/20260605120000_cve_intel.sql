-- Global CVE intelligence table.
--
-- Unlike every other table, this is NOT org-scoped: it is shared reference data
-- (CISA KEV + FIRST EPSS, later NVD/OSV) synced by a backend job. Every org reads
-- the same rows; correlation against an asset's findings is a deterministic JOIN
-- on cve_id, replacing the LLM "recall CVE data from memory" step (cheaper + accurate).
--
-- Writes happen ONLY through the service-role client (the sync job), which bypasses
-- RLS. So we enable RLS with a read-only policy for authenticated users and grant
-- no INSERT/UPDATE/DELETE policy at all.

create table cve_intel (
  cve_id            text primary key,            -- e.g. CVE-2021-44228

  -- Severity (from KEV/NVD where available)
  cvss_score        numeric,                     -- 0.0 - 10.0
  cvss_severity     text,                        -- critical/high/medium/low/none

  -- EPSS (FIRST) — likelihood of exploitation in the next 30 days
  epss_score        numeric,                     -- 0.0 - 1.0 probability
  epss_percentile   numeric,                     -- 0.0 - 1.0 percentile rank

  -- CISA KEV — known exploited in the wild (the "this is urgent" signal)
  in_kev            boolean not null default false,
  kev_date_added    date,
  kev_ransomware    boolean not null default false,  -- knownRansomwareCampaignUse
  kev_name          text,
  short_description text,

  refs              jsonb not null default '[]',  -- reference URLs (advisories, etc.)

  source_updated_at timestamptz,                  -- when the upstream feed was published
  updated_at        timestamptz not null default now()
);

-- Prioritisation queries: "most exploitable first", "what's in KEV".
create index cve_intel_epss_idx on cve_intel (epss_score desc);
create index cve_intel_kev_idx  on cve_intel (in_kev) where in_kev = true;

alter table cve_intel enable row level security;

-- Authenticated users may READ the shared catalog. No write policy → only the
-- service-role sync job can populate it.
create policy "authenticated_read" on cve_intel
  for select
  to authenticated
  using (true);
