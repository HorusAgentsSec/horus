-- Community verdicts — the cross-customer false-positive / exploitation flywheel.
--
-- finding_verdicts is per-org: it learns from YOUR team's feedback. This table aggregates that
-- feedback ACROSS all orgs, anonymously, so a brand-new customer benefits on day one from what the
-- whole fleet has learned ("nmap http-csrf on a static page is almost always noise"). This is the
-- data network effect — it gets better with every customer and a competitor calling an LLM API
-- can't replicate it without the same install base.
--
-- Privacy by construction:
--   * Keyed only by the generalizable signature (svc:nginx / cve:CVE-… / title:…) — never a hostname,
--     finding id, or org id. The signature carries no customer data.
--   * k-anonymity: a signature only yields a community verdict once at least `min_orgs` DISTINCT orgs
--     agree, so no single org's idiosyncratic call leaks to others or is identifiable.
--   * Stores aggregate counts, not rows.
--
-- Refreshed by refresh_community_verdicts() on a daily job. One row per signature.

create table community_verdicts (
  signature       text primary key,
  fp_orgs         integer not null default 0,   -- distinct orgs whose latest verdict is false_positive
  confirmed_orgs  integer not null default 0,   -- distinct orgs whose latest verdict is confirmed
  total_orgs      integer not null default 0,   -- distinct orgs with any verdict for this signature
  verdict         text,                          -- derived community verdict: false_positive | confirmed | null
  updated_at      timestamptz not null default now()
);

-- Anonymized aggregate; readable by any authenticated user, written only by the service-role job.
alter table community_verdicts enable row level security;
create policy "authenticated_read" on community_verdicts using (true);

-- Recompute the aggregate from finding_verdicts. A signature becomes a community verdict only when
-- >= min_orgs distinct orgs have weighed in AND a strong majority (>= ratio) agree.
-- security definer + raised timeout: the GROUP BY can scan the whole verdict history.
create or replace function refresh_community_verdicts(min_orgs int default 3, ratio numeric default 0.6)
returns void
language sql
security definer
set search_path = public
set statement_timeout = '120s'
as $$
  with latest as (
    -- one row per (org, signature): that org's most recent call
    select distinct on (org_id, signature) org_id, signature, verdict
    from finding_verdicts
    order by org_id, signature, created_at desc
  ),
  agg as (
    select
      signature,
      count(*) filter (where verdict = 'false_positive') as fp_orgs,
      count(*) filter (where verdict = 'confirmed')       as confirmed_orgs,
      count(*)                                            as total_orgs
    from latest
    group by signature
  )
  insert into community_verdicts (signature, fp_orgs, confirmed_orgs, total_orgs, verdict, updated_at)
  select
    signature, fp_orgs, confirmed_orgs, total_orgs,
    case
      when total_orgs >= min_orgs and fp_orgs::numeric / total_orgs >= ratio then 'false_positive'
      when total_orgs >= min_orgs and confirmed_orgs::numeric / total_orgs >= ratio then 'confirmed'
      else null
    end,
    now()
  from agg
  on conflict (signature) do update set
    fp_orgs        = excluded.fp_orgs,
    confirmed_orgs = excluded.confirmed_orgs,
    total_orgs     = excluded.total_orgs,
    verdict        = excluded.verdict,
    updated_at     = excluded.updated_at;
$$;
