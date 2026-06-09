-- Add 'canceled' as a valid status for jobs and adversarial_runs so the UI
-- can distinguish a user-initiated stop from a genuine failure.

ALTER TABLE jobs DROP CONSTRAINT IF EXISTS jobs_status_check;
ALTER TABLE jobs ADD CONSTRAINT jobs_status_check
  CHECK (status IN ('running', 'completed', 'failed', 'canceled'));

ALTER TABLE adversarial_runs DROP CONSTRAINT IF EXISTS adversarial_runs_status_check;
ALTER TABLE adversarial_runs ADD CONSTRAINT adversarial_runs_status_check
  CHECK (status IN ('running', 'completed', 'failed', 'canceled'));
