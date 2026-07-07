-- Finding verdict memory — the reflection loop that makes the platform get smarter.
--
-- Every time a human passes judgement on a finding (marks it a false positive, resolves it,
-- accepts the risk, or approves a remediation), we record that verdict against a *generalizable
-- signature* of the finding (e.g. the product "nginx", or an nmap script title) rather than the
-- one-off per-asset fingerprint. On future scans the ValidationAgent recalls these verdicts and
-- applies them as a prior: a finding a teammate already called a false positive is auto-suppressed
-- without spending a debate, and one already confirmed is trusted. Human feedback compounds into
-- accuracy — the "configure once, it improves on its own" loop.
--
-- Append-only (one row per judgement) so the history is auditable; recall takes the latest per
-- signature.

create table finding_verdicts (
  id          uuid primary key default gen_random_uuid(),
  org_id      uuid references organizations(id) on delete cascade not null,
  signature   text not null,          -- generalizable finding signature (svc:/cve:/title:)
  verdict     text not null check (verdict in ('false_positive', 'confirmed')),
  source      text not null,          -- what produced it: 'status' | 'suggestion'
  finding_id  uuid references findings(id) on delete set null,  -- the finding that triggered it
  created_by  uuid references profiles(id) on delete set null,
  created_at  timestamptz not null default now()
);

-- Recall path: latest verdict for an org's signatures.
create index finding_verdicts_lookup_idx on finding_verdicts (org_id, signature, created_at desc);

alter table finding_verdicts enable row level security;

-- Org isolation: members read/write only their org's verdicts (recording happens through the
-- authed client on a human action; recall in the pipeline uses the service role, which bypasses RLS).
create policy "org_isolation" on finding_verdicts
  using (org_id = current_org_id())
  with check (org_id = current_org_id());
