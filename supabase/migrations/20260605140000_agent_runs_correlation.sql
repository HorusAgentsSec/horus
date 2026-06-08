-- Allow the new CorrelationAgent (CPE->CVE correlation) to log its runs.
-- The original check (001_initial.sql) hardcoded the agent type list; without this,
-- _log_agent_start() would raise 23514 and the agent would silently never run.

alter table agent_runs drop constraint if exists agent_runs_agent_type_check;

alter table agent_runs
  add constraint agent_runs_agent_type_check
  check (agent_type in (
    'recon', 'analyst', 'correlation', 'threat_intel',
    'remediation', 'risk_manager', 'reporter'
  ));
