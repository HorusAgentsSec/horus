-- Community sharing for phishing templates
ALTER TABLE phishing_templates
  ADD COLUMN IF NOT EXISTS is_public boolean NOT NULL DEFAULT false;

-- Allow any authenticated user to read public templates (bypasses org isolation for public rows)
CREATE POLICY "phishing_templates_read_public"
  ON phishing_templates
  FOR SELECT
  USING (is_public = true);
