-- severity_rank: columna generada para ordenar findings por gravedad real.
-- order("severity") en PostgREST ordena el texto alfabeticamente
-- (critical, high, info, low, medium), que NO es orden de riesgo. Esta columna
-- da el rank numerico y se mantiene sola (STORED generated).
alter table findings
  add column if not exists severity_rank int
  generated always as (
    case severity
      when 'critical' then 0
      when 'high'     then 1
      when 'medium'   then 2
      when 'low'      then 3
      else 4
    end
  ) stored;

create index if not exists findings_severity_rank_idx
  on findings (org_id, severity_rank, created_at desc);
