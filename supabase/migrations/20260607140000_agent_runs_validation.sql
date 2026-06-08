-- Allow the new ValidationAgent (red/blue debate) to log its runs.
-- Same hazard as the correlation agent (20260605140000): the agent_type check is a hardcoded
-- list, so without adding 'validation' here _log_agent_start() raises 23514 and the validation
-- step silently never runs (and the scan is marked failed).

alter table agent_runs drop constraint if exists agent_runs_agent_type_check;

alter table agent_runs
  add constraint agent_runs_agent_type_check
  check (agent_type in (
    'recon', 'analyst', 'correlation', 'threat_intel', 'validation',
    'remediation', 'risk_manager', 'reporter'
  ));
