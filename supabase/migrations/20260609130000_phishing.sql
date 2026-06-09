-- Phishing simulation campaigns and per-target tracking.
-- Only admins can create/launch campaigns; the track endpoint is public (no JWT).

CREATE TABLE phishing_campaigns (
    id           uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    org_id       uuid        NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    name         text        NOT NULL,
    objective    text        NOT NULL CHECK (objective IN ('click', 'credentials', 'report')),
    status       text        NOT NULL DEFAULT 'draft'
                             CHECK (status IN ('draft', 'running', 'completed', 'cancelled')),
    asset_ids    jsonb       NOT NULL DEFAULT '[]',
    created_by   uuid        REFERENCES profiles(id) ON DELETE SET NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    launched_at  timestamptz,
    completed_at timestamptz
);

-- One row per (campaign × employee). tracking_token is the honeypot key.
CREATE TABLE phishing_targets (
    id               uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    campaign_id      uuid        NOT NULL REFERENCES phishing_campaigns(id) ON DELETE CASCADE,
    org_id           uuid        NOT NULL,
    employee_id      uuid,
    employee_name    text        NOT NULL,
    employee_email   text        NOT NULL,
    tracking_token   text        NOT NULL UNIQUE,
    email_subject    text,
    email_pretext    text,
    sent_at          timestamptz,
    clicked_at       timestamptz,
    reported_at      timestamptz
);

CREATE INDEX phishing_targets_campaign ON phishing_targets (campaign_id);
CREATE INDEX phishing_targets_token    ON phishing_targets (tracking_token);

-- RLS — org-scoped for authenticated users
ALTER TABLE phishing_campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE phishing_targets   ENABLE ROW LEVEL SECURITY;

CREATE POLICY phishing_campaigns_org ON phishing_campaigns
    FOR ALL USING (org_id = current_org_id());

CREATE POLICY phishing_targets_org ON phishing_targets
    FOR ALL USING (org_id = current_org_id());

-- The track endpoint runs without JWT and uses service-role on the backend,
-- so no additional policy is needed for the public click handler.
