-- Phishing email templates: reusable templates for simulation campaigns
CREATE TABLE IF NOT EXISTS phishing_templates (
  id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  org_id      uuid NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
  name        text NOT NULL,
  subject     text NOT NULL DEFAULT '',
  body_html   text NOT NULL DEFAULT '',
  created_by  uuid,
  created_at  timestamptz DEFAULT now(),
  updated_at  timestamptz DEFAULT now()
);

ALTER TABLE phishing_templates ENABLE ROW LEVEL SECURITY;

CREATE POLICY "phishing_templates_org_isolation"
  ON phishing_templates
  FOR ALL
  USING (org_id = current_org_id());

-- Link campaigns to an optional template
ALTER TABLE phishing_campaigns
  ADD COLUMN IF NOT EXISTS template_id uuid REFERENCES phishing_templates(id) ON DELETE SET NULL;
