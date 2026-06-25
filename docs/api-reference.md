# Horus API Reference

**Base URL:** `https://api.horusagents.com/api`

All endpoints require authentication unless otherwise noted. Pass a JWT Bearer token or an API key.

```
Authorization: Bearer <token>
# or
X-Api-Key: hrs_<key>
```

Roles: `viewer` < `analyst` < `admin`. Each endpoint notes the minimum role required.

---

## Authentication

Horus uses Supabase Auth. Obtain a JWT by signing in through the Supabase Auth SDK or the Horus dashboard. API keys (`hrs_...`) are a machine-to-machine alternative scoped to a role; see [API Keys](#api-keys).

**Stream ticket** (SSE only): some endpoints that use Server-Sent Events cannot receive an `Authorization` header. Call the corresponding `/stream-ticket` endpoint first to get a short-lived single-use ticket (30 s TTL), then pass it as `?ticket=<ticket>` in the SSE URL.

---

## Dashboard

### `GET /api/dashboard/stats`

High-level counts for the dashboard summary card.

- **Auth:** any authenticated user
- **Response:** `total_assets`, `open_findings_by_severity` (object), `recent_scans` (array, last 5), `pending_suggestions`

---

### `GET /api/dashboard/metrics`

Actionable security metrics: SSVC breakdown, KEV exposure, asset coverage, MTTR, findings trend, and top risky assets.

- **Auth:** any authenticated user
- **Response:** `ssvc` (act/attend/track_star/track/none counts), `kev_active`, `asset_coverage` (scanned/total/pct), `findings_trend` (new_this_week/new_prev_week/resolved_this_week), `mttr_critical_days`, `top_risky_assets` (array, max 5), `open_by_severity`

---

## Scans

### `GET /api/scans`

List scans for the org, newest first.

- **Auth:** any authenticated user
- **Query params:** `page` (default 1), `per_page` (default 20)
- **Response:** array of scan objects; each includes `assets(name, host)` and `triggered_by_label`

---

### `POST /api/scans`

Trigger a scan against a single asset.

- **Auth:** analyst+
- **Body:** `asset_id` (string, required), `tools` (array of tool names)
- **Response:** `{ scan_id, status: "pending" }` — HTTP 202

---

### `POST /api/scans/scan-all`

Queue a scan for every active asset in the org.

- **Auth:** analyst+
- **Body (optional):** `tools` (array)
- **Response:** `{ queued, scan_ids }`

---

### `POST /api/scans/cancel-active`

Cancel all pending or running scans for the org.

- **Auth:** analyst+
- **Response:** `{ canceled }` (count)

---

### `GET /api/scans/{scan_id}`

Full scan detail with agent runs and findings (noise hidden).

- **Auth:** any authenticated user
- **Response:** scan object + `agent_runs` array + `findings` array

---

### `POST /api/scans/{scan_id}/cancel`

Cancel a specific scan. Only works when status is `pending` or `running`.

- **Auth:** analyst+
- **Response:** updated scan object

---

## Findings

### `GET /api/findings`

List findings with optional filters. Noise findings are hidden by default.

- **Auth:** any authenticated user
- **Query params:** `severity`, `status`, `asset_id`, `cve_id`, `tool`, `order_by` (severity), `include_noise` (bool), `page`, `per_page` (default 50)
- **Response:** `{ items, noise_count }`

---

### `GET /api/findings/export`

Stream all findings as JSONL or CSV for SIEM ingestion.

- **Auth:** any authenticated user
- **Query params:** `format` (jsonl | csv, default jsonl), `include_noise` (bool)
- **Response:** streaming file download; fields: `id`, `title`, `severity`, `cvss_score`, `asset_host`, `cves`, `first_seen_at`, `last_seen_at`, `status`

---

### `POST /api/findings/import`

Import findings from a Nuclei JSONL file or generic JSON array. Deduplicates on re-import.

- **Auth:** any authenticated user
- **Body (multipart):** `file` (upload), `source` (nuclei | generic)
- **Response:** `{ imported, skipped, total }`

---

### `POST /api/findings/bulk`

Update the status of multiple findings at once.

- **Auth:** any authenticated user
- **Body:** `ids` (array of UUIDs), `action` (mark_false_positive | accept_risk | mark_open | mark_resolved)
- **Response:** `{ updated }` (count)

---

### `GET /api/findings/{finding_id}`

Get a single finding with `incident_count` (how many incidents it belongs to).

- **Auth:** any authenticated user
- **Response:** finding object + `incident_count`

---

### `PATCH /api/findings/{finding_id}`

Update the status of a finding. Records a human verdict for the reflection loop.

- **Auth:** any authenticated user
- **Body:** `status` (open | resolved | false_positive | accepted_risk)
- **Response:** updated finding object

---

### `GET /api/findings/{finding_id}/suggestions`

List AI remediation suggestions for a finding.

- **Auth:** any authenticated user
- **Response:** array of agent suggestion objects

---

## Assets

### `GET /api/assets`

List all assets (active and inactive) for the org.

- **Auth:** any authenticated user
- **Response:** array of asset objects

---

### `POST /api/assets`

Add a new asset. Validates the host/CIDR before saving.

- **Auth:** analyst+
- **Body:** `name`, `host`, `type`, `is_internal` (bool)
- **Response:** created asset object — HTTP 201

---

### `GET /api/assets/{asset_id}`

Get a single asset.

- **Auth:** any authenticated user
- **Response:** asset object

---

### `PATCH /api/assets/{asset_id}`

Update an asset's fields. Re-validates `host` if changed.

- **Auth:** analyst+
- **Body:** any subset of `name`, `host`, `type`, `is_internal`, `is_active`
- **Response:** updated asset object

---

### `DELETE /api/assets/{asset_id}`

Soft-delete an asset (sets `deleted_at`, marks `is_active: false`).

- **Auth:** admin
- **Response:** HTTP 204

---

### `GET /api/assets/{asset_id}/scans`

Last 20 scans for a specific asset.

- **Auth:** any authenticated user
- **Response:** array of scan objects with `triggered_by_label`

---

### `GET /api/assets/{asset_id}/findings/summary`

Open finding counts by severity for an asset.

- **Auth:** any authenticated user
- **Response:** `{ open_by_severity, total }`

---

### `GET /api/assets/{asset_id}/inventory`

Software inventory detected on the asset.

- **Auth:** any authenticated user
- **Response:** array of `{ product, version, port, service_name, last_seen_at }`

---

## Incidents

### `GET /api/incidents`

List incidents with pagination and optional filters.

- **Auth:** any authenticated user
- **Query params:** `status` (open | in_progress | resolved | closed), `severity`, `assignee_id`, `page`, `per_page` (default 25)
- **Response:** `{ items, page, per_page, total }`. Each item includes `finding_count` and `assignee` (enriched with name/email).

---

### `POST /api/incidents`

Create a new incident, optionally linking findings at creation time.

- **Auth:** analyst+
- **Body:** `title`, `description`, `severity` (critical | high | medium | low), `assignee_id`, `sla_deadline` (ISO 8601), `finding_ids` (array)
- **Response:** created incident object — HTTP 201

---

### `GET /api/incidents/{incident_id}`

Full incident detail: metadata, linked findings, and notes.

- **Auth:** any authenticated user
- **Response:** incident object + `findings` array + `notes` array; persons enriched with name/email

---

### `PATCH /api/incidents/{incident_id}`

Update incident fields. Setting `status: closed` stamps `closed_at`.

- **Auth:** analyst+
- **Body:** any subset of `title`, `status`, `severity`, `assignee_id`, `sla_deadline`
- **Response:** updated incident object

---

### `DELETE /api/incidents/{incident_id}`

Soft-close an incident (sets status to `closed`).

- **Auth:** admin
- **Response:** closed incident object

---

### `POST /api/incidents/{incident_id}/findings`

Link one or more findings to an incident. Ignores findings not owned by the org.

- **Auth:** analyst+
- **Body:** `finding_ids` (array)
- **Response:** `{ linked }` (count)

---

### `DELETE /api/incidents/{incident_id}/findings/{finding_id}`

Unlink a finding from an incident (soft-delete of the join row).

- **Auth:** analyst+
- **Response:** HTTP 204

---

### `POST /api/incidents/{incident_id}/notes`

Add an append-only note to an incident.

- **Auth:** any authenticated user
- **Body:** `body` (string, 1–10 000 chars)
- **Response:** created note object with `author` enriched — HTTP 201

---

## Phishing

### Employees

#### `GET /api/phishing/employees`

List employees with credential breach data joined.

- **Auth:** analyst+
- **Response:** array of employee objects including `credential_breaches`

---

#### `POST /api/phishing/employees`

Add a single employee.

- **Auth:** admin
- **Body:** `email`, `full_name`, `department`
- **Response:** created employee object — HTTP 201

---

#### `POST /api/phishing/employees/import`

Bulk-import employees from CSV text.

- **Auth:** admin
- **Body:** `csv_text` (raw CSV; columns: email, full_name, department)
- **Response:** `{ imported, errors }`

---

#### `DELETE /api/phishing/employees/{employee_id}`

Soft-delete an employee record.

- **Auth:** admin
- **Response:** HTTP 204

---

### Templates

#### `GET /api/phishing/templates`

List phishing email templates for the org.

- **Auth:** analyst+
- **Response:** array of template objects

---

#### `POST /api/phishing/templates`

Create a phishing template manually.

- **Auth:** admin
- **Body:** `name`, `subject`, `body_html`, `is_public` (bool)
- **Response:** created template — HTTP 201

---

#### `POST /api/phishing/templates/generate`

AI-generate a phishing template and save it.

- **Auth:** admin
- **Body:** `name`, `objective` (click | credentials | report), `scenario` (free text), `is_public`
- **Response:** saved template + `pretext` (AI-written context) — HTTP 201

---

#### `GET /api/phishing/templates/community`

List all public templates (system library + user-contributed).

- **Auth:** analyst+
- **Response:** array of templates; each includes `org_name` and `is_own`

---

#### `GET /api/phishing/templates/{template_id}`

Get a single template owned by the org.

- **Auth:** analyst+
- **Response:** template object

---

#### `PATCH /api/phishing/templates/{template_id}`

Update a template.

- **Auth:** admin
- **Body:** any subset of `name`, `subject`, `body_html`, `is_public`
- **Response:** updated template

---

#### `DELETE /api/phishing/templates/{template_id}`

Soft-delete a template.

- **Auth:** admin
- **Response:** HTTP 204

---

#### `POST /api/phishing/templates/{template_id}/fork`

Clone a public (or system library) template into the org's library.

- **Auth:** admin
- **Response:** new template object — HTTP 201

---

### Campaigns

#### `GET /api/phishing/campaigns`

List phishing campaigns for the org.

- **Auth:** analyst+
- **Response:** array of campaign objects

---

#### `POST /api/phishing/campaigns`

Create a new campaign.

- **Auth:** admin
- **Body:** `name`, `objective` (click | credentials | report), `context_asset_ids`, `schedule_cron`, `template_id`
- **Response:** created campaign — HTTP 201

---

#### `GET /api/phishing/campaigns/{campaign_id}`

Get a single campaign.

- **Auth:** analyst+
- **Response:** campaign object

---

#### `PATCH /api/phishing/campaigns/{campaign_id}`

Update a campaign.

- **Auth:** admin
- **Body:** any subset of `name`, `objective`, `context_asset_ids`, `schedule_cron`, `status`
- **Response:** updated campaign

---

#### `DELETE /api/phishing/campaigns/{campaign_id}`

Soft-delete a campaign.

- **Auth:** admin
- **Response:** HTTP 204

---

#### `POST /api/phishing/campaigns/{campaign_id}/launch`

Generate personalised phishing emails and send them (when SMTP is configured). Each target gets a unique tracking token.

- **Auth:** admin
- **Body:** `employee_ids` (array)
- **Response:** `{ targets, send_errors }`

---

#### `GET /api/phishing/campaigns/{campaign_id}/results`

Campaign click/credential/report summary and per-target detail.

- **Auth:** analyst+
- **Response:** `{ campaign, summary: { total, clicked, entered_credentials, reported, safe }, targets }`

---

## Iris

Iris is the Horus endpoint-monitoring daemon. Two auth planes apply: user endpoints use the standard JWT/API-key flow; the agent endpoint uses the `X-Iris-Key: irs_<key>` header exclusively.

### User endpoints

#### `POST /api/iris/agents/register`

Register a new Iris agent. The API key is returned once and never shown again.

- **Auth:** any authenticated user
- **Body:** `name`, `asset_id` (optional, must belong to org)
- **Response:** `{ agent_id, key_prefix, api_key }` — HTTP 201

---

#### `GET /api/iris/agents`

List all Iris agents for the org with pending/total event counts.

- **Auth:** any authenticated user
- **Response:** array of agent objects including `pending_events`, `total_events`, `status`, `last_seen_at`

---

#### `GET /api/iris/agents/{agent_id}/events`

Most recent events for a specific agent (max 200).

- **Auth:** any authenticated user
- **Query params:** `limit` (default 50, max 200)
- **Response:** array of `{ id, event_type, severity, title, payload, received_at }`

---

#### `DELETE /api/iris/agents/{agent_id}`

Soft-delete an Iris agent. Events are preserved.

- **Auth:** any authenticated user
- **Response:** HTTP 204

---

#### `POST /api/iris/agents/{agent_id}/process`

Batch all pending events for an agent into a scan and submit it to the AI pipeline. Returns immediately.

- **Auth:** any authenticated user
- **Response:** `{ scan_id, events_processed }` — HTTP 202

---

#### `GET /api/iris/agents/{agent_id}/ai-analysis`

Live, read-only AI triage preview for a specific agent. Cached for 30 s to limit LLM calls.

- **Auth:** any authenticated user
- **Response:** `{ analyzed, groups, prompt, response, model }` or a budget-exceeded message

---

### Agent endpoint

#### `POST /api/iris/events`

Daemon reports a batch of events. Updates the agent heartbeat. High-confidence threats (agent tamper, brute-force, C2 connections) create findings and in-app alerts immediately.

- **Auth:** `X-Iris-Key: irs_<key>` header (no JWT)
- **Body:** `agent_id`, `hostname`, `ip`, `events` (array of `{ event_type, severity, title, payload }`)
- **Valid event types:** `file_change`, `new_process`, `new_listener`, `new_connection`, `auth_event`, `log_anomaly`
- **Response:** `{ received }` — HTTP 202

---

#### `GET /api/iris/ping`

Validate key and check server reachability.

- **Auth:** `X-Iris-Key: irs_<key>`
- **Response:** `{ ok, agent, agent_id }`

---

## Watchtower

Watchtower continuously correlates the software inventory against newly known-exploited CVEs.

### `GET /api/watchtower/alerts`

Most recent exposure alerts (up to 200), with asset name joined.

- **Auth:** any authenticated user
- **Response:** array of alert objects

---

### `GET /api/watchtower/inventory`

Persisted software inventory across all assets (up to 500 rows), with asset name joined.

- **Auth:** any authenticated user
- **Response:** array of inventory items

---

### `POST /api/watchtower/run`

Trigger an on-demand Watchtower pass in the background. Returns immediately.

- **Auth:** admin
- **Response:** `{ status: "started" }`

---

### `POST /api/watchtower/stream-ticket`

Mint a short-lived single-use ticket for the SSE stream.

- **Auth:** admin
- **Response:** `{ ticket }`

---

### `GET /api/watchtower/stream?ticket=<ticket>`

SSE stream of a live Watchtower pass. Authenticate via ticket from `/stream-ticket`.

- **Auth:** stream ticket
- **Response:** `text/event-stream`; each event is `data: { msg }` or `data: { done: true, result }`

---

### `POST /api/watchtower/ransomware-check`

On-demand ransomware.live check for the org's domain.

- **Auth:** admin
- **Response:** check results + `status: "completed"`

---

### `GET /api/watchtower/ransomware-victims`

All ransomware.live findings for the org.

- **Auth:** any authenticated user
- **Response:** array of finding objects where `raw_data.source == "ransomware.live"`

---

## Adversarial

The adversarial engine runs automated Red-Blue cycles and persists findings in `red_findings`.

### `GET /api/adversarial/findings`

List red-team findings with optional filters.

- **Auth:** any authenticated user
- **Query params:** `status`, `severity`, `asset_id`, `category`, `page`, `per_page` (default 25)
- **Response:** array of red finding objects with `assets(name, host)`

---

### `GET /api/adversarial/findings/{finding_id}`

Get a single red finding.

- **Auth:** any authenticated user
- **Response:** red finding object

---

### `PATCH /api/adversarial/findings/{finding_id}`

Update `status` or `notes` on a red finding.

- **Auth:** analyst+
- **Body:** `status` (open | responded | accepted | false_positive), `notes`
- **Response:** updated red finding

---

### `DELETE /api/adversarial/findings/{finding_id}`

Soft-delete a red finding.

- **Auth:** analyst+
- **Response:** HTTP 204

---

### `POST /api/adversarial/run`

Trigger a Red-Blue adversarial cycle. Returns a `run_id` for SSE streaming.

- **Auth:** admin
- **Response:** `{ status: "queued", org_id, run_id }` — HTTP 202

---

### `GET /api/adversarial/runs/{cycle_run_id}/stream`

SSE stream for a live or historical adversarial cycle.

- **Auth:** any authenticated user
- **Response:** `text/event-stream`; each event is a JSON object; final event is `{ type: "done" }`

---

### `GET /api/adversarial/history`

List historical adversarial run records.

- **Auth:** any authenticated user
- **Query params:** `page`, `per_page` (default 15)
- **Response:** array of `{ id, status, findings_created, responses_created, started_at, completed_at, triggered_by }`

---

### `GET /api/adversarial/stats`

Summary counts by status, severity, and category.

- **Auth:** any authenticated user
- **Response:** `{ total, by_status, by_severity, by_category }`

---

### `GET /api/adversarial/schedules`

List adversarial run schedules with last-run and next-run info.

- **Auth:** admin
- **Response:** array of schedule objects

---

### `POST /api/adversarial/schedules`

Create an adversarial schedule.

- **Auth:** admin
- **Body:** `name` (required), `cron_expression` (required)
- **Response:** created schedule — HTTP 201

---

### `PATCH /api/adversarial/schedules/{schedule_id}`

Update a schedule's name, cron expression, or enabled flag.

- **Auth:** admin
- **Body:** any subset of `name`, `cron_expression`, `enabled`
- **Response:** updated schedule

---

### `DELETE /api/adversarial/schedules/{schedule_id}`

Soft-delete an adversarial schedule and unregister the cron job.

- **Auth:** admin
- **Response:** HTTP 204

---

## Integrations

### `GET /api/integrations`

List notification/ticketing integrations. Secret fields are masked.

- **Auth:** admin
- **Response:** array of integration objects with `config` secrets replaced by `••••••••`

---

### `POST /api/integrations`

Create a new integration.

- **Auth:** admin
- **Body:** `type` (slack | teams | email | pagerduty | opsgenie | webhook | jira | aws | gcp), `config` (object), `enabled` (bool)
- **Response:** created integration (secrets masked) — HTTP 201

---

### `PATCH /api/integrations/{integration_id}`

Update an integration.

- **Auth:** admin
- **Body:** any subset of `type`, `config`, `enabled`
- **Response:** updated integration (secrets masked)

---

### `DELETE /api/integrations/{integration_id}`

Soft-delete an integration.

- **Auth:** admin
- **Response:** HTTP 204

---

### `PATCH /api/integrations/{integration_id}/board-report`

Opt an email integration in or out of the monthly board posture report.

- **Auth:** admin
- **Body:** `enabled` (bool)
- **Response:** updated integration

---

### `POST /api/integrations/{integration_id}/test`

Send a test message using the stored (unredacted) config.

- **Auth:** admin
- **Response:** `{ ok: true }` or HTTP 400 with error detail

---

### Jira

#### `GET /api/integrations/jira/status`

Check whether Jira is configured and enabled (safe for any user, no secrets exposed).

- **Auth:** any authenticated user
- **Response:** `{ configured, enabled, project_key }`

---

#### `POST /api/integrations/jira/test`

Test the Jira connection using stored credentials.

- **Auth:** admin
- **Response:** `{ ok, account }` or HTTP 400 with diagnostic detail

---

#### `POST /api/integrations/jira/tickets`

Create a Jira issue from a finding. Idempotent: returns the existing ticket if one already exists.

- **Auth:** analyst+
- **Body:** `finding_id` (UUID)
- **Response:** `{ ticket_key, ticket_url, created (bool), ... }` — HTTP 201

---

#### `GET /api/integrations/jira/tickets?finding_id=<uuid>`

List existing Jira ticket references for a finding.

- **Auth:** any authenticated user
- **Response:** array of `{ ticket_key, ticket_url, ... }`

---

## Jobs

### `GET /api/jobs`

List recent job executions, newest first. Covers scan schedules, discovery runs, CVE syncs, Watchtower passes, posture snapshots, board reports, and adversarial cycles.

- **Auth:** any authenticated user
- **Query params:** `job_type`, `status` (running | completed | failed | canceled), `limit` (max 500, default 100)
- **Response:** array of job objects

---

### `GET /api/jobs/stats`

Health summary over the last 100 jobs: counts by status and the most recent failure.

- **Auth:** any authenticated user
- **Response:** `{ by_status, last_failure, sampled }`

---

### `POST /api/jobs/{job_id}/cancel`

Stop a running job. Marks the DB row canceled immediately and sets the cooperative cancel flag.

- **Auth:** admin
- **Response:** `{ status: "canceled", job_id }`

---

## Schedules

### `GET /api/schedules`

List scan schedules enriched with `last_run` (from job history) and `next_run` (from the live scheduler).

- **Auth:** any authenticated user
- **Response:** array of schedule objects

---

### `POST /api/schedules`

Create a scan schedule.

- **Auth:** any authenticated user
- **Body:** schedule fields (see `ScheduleCreate` schema)
- **Response:** created schedule — HTTP 201

---

### `PATCH /api/schedules/{schedule_id}`

Update a schedule and re-register the cron job live.

- **Auth:** any authenticated user
- **Body:** schedule fields (see `ScheduleUpdate` schema)
- **Response:** updated schedule

---

### `DELETE /api/schedules/{schedule_id}`

Soft-delete a schedule and unregister the cron job.

- **Auth:** any authenticated user
- **Response:** HTTP 204

---

## Notifications

### `GET /api/notifications`

List unread notifications for the current user.

- **Auth:** any authenticated user
- **Response:** array of notification objects

---

### `PATCH /api/notifications/{notification_id}/read`

Mark a notification as read.

- **Auth:** any authenticated user
- **Response:** HTTP 204

---

### `DELETE /api/notifications/{notification_id}`

Soft-delete a notification.

- **Auth:** any authenticated user
- **Response:** HTTP 204

---

## Team

### `GET /api/team`

List org members (active) and pending invitations.

- **Auth:** any authenticated user
- **Response:** `{ members: [{ id, role, full_name, email, created_at }], pending: [...] }`

---

### `POST /api/team/invite`

Invite a user to the org. Creates a Supabase auth user if the email is new; sets `must_change_password` so they are forced to set a real password on first login.

- **Auth:** admin
- **Body:** `email`, `role` (admin | analyst | viewer)
- **Response:** `{ user_id, email, role, temp_password }` — HTTP 201. `temp_password` is `null` if the account already existed.

---

### `PATCH /api/team/{user_id}/role`

Change a member's role.

- **Auth:** admin
- **Body:** `role` (admin | analyst | viewer)
- **Response:** updated profile object

---

### `DELETE /api/team/{user_id}`

Remove a member (soft-delete). Cannot remove yourself.

- **Auth:** admin
- **Response:** HTTP 204

---

## Settings

Settings are per-org. Secret values are never echoed back; GET returns only whether each key is set.

### `GET /api/settings`

Get current org settings.

- **Auth:** admin
- **Response:** `{ shodan_api_key_set, breach_directory_api_key_set, intelx_api_key_set, iris_triage_interval_minutes, token_limit_daily, token_limit_weekly, token_limit_monthly }`

---

### `PUT /api/settings`

Update org settings. Send the mask placeholder `••••••••` to leave a secret unchanged; send a blank string to clear it.

- **Auth:** admin
- **Body:** any subset of `shodan_api_key`, `breach_directory_api_key`, `intelx_api_key`, `iris_triage_interval_minutes` (5–1440), `token_limit_daily`, `token_limit_weekly`, `token_limit_monthly`
- **Response:** same shape as `GET /api/settings`

---

### `DELETE /api/settings/organization`

Permanently delete the organization and all its data (GDPR right to erasure). Irreversible.

- **Auth:** admin
- **Response:** HTTP 204

---

## Metrics

### `GET /api/metrics/tokens`

AI token consumption and model usage metrics for the org.

- **Auth:** any authenticated user
- **Query params:** `days` (default 30)
- **Response:** `{ total_tokens, by_agent, by_model, daily_usage: [{ date, tokens }] }`

---

## Discovery

### `GET /api/discovery`

List discovery sources for the org.

- **Auth:** any authenticated user
- **Response:** array of discovery source objects

---

### `POST /api/discovery`

Create a discovery source.

- **Auth:** analyst+
- **Body:** `kind` (domain | network), `domain` (required for domain kind), `network_cidr` (required for network kind; must be a private RFC-1918 CIDR), `cron_expression`, `enabled`
- **Response:** created source — HTTP 201

---

### `PATCH /api/discovery/{source_id}`

Update a discovery source and re-register the cron job.

- **Auth:** analyst+
- **Body:** any subset of source fields
- **Response:** updated source

---

### `DELETE /api/discovery/{source_id}`

Soft-delete a discovery source and unregister the cron job.

- **Auth:** analyst+
- **Response:** HTTP 204

---

### `POST /api/discovery/{source_id}/run`

Kick off a discovery pass in the background. Returns immediately.

- **Auth:** analyst+
- **Response:** `{ status: "started" }`

---

## Cloud

Cloud audit credentials are stored as integrations of type `aws` or `gcp`; manage them with the [Integrations](#integrations) endpoints.

### `POST /api/cloud/aws/{integration_id}/audit`

Start an AWS security audit in the background.

- **Auth:** admin
- **Response:** `{ status: "started" }`

---

### `POST /api/cloud/gcp/{integration_id}/audit`

Start a GCP security audit in the background.

- **Auth:** admin
- **Response:** `{ status: "started" }`

---

### `GET /api/cloud/audits`

List recent cloud-audit job runs for the org (status, duration, summary).

- **Auth:** analyst+
- **Response:** array of job objects (up to 20)

---

## API Keys

API keys (`hrs_...`) are machine credentials scoped to an org and role. Pass them via the `X-Api-Key` header.

### `GET /api/api-keys`

List active (non-revoked) API keys for the org. Secrets are never returned after creation.

- **Auth:** admin
- **Response:** array of `{ id, name, key_prefix, role, created_at, last_used_at }`

---

### `POST /api/api-keys`

Create an API key. The full secret is returned exactly once.

- **Auth:** admin
- **Body:** `name`, `role` (analyst | admin)
- **Response:** `{ id, name, key_prefix, secret, role, created_at }` — HTTP 201. Store the `secret` immediately.

---

### `DELETE /api/api-keys/{key_id}`

Revoke an API key. Requests made with the revoked key will return 401 immediately.

- **Auth:** admin
- **Response:** HTTP 204

---

## Posture

### `GET /api/posture/timeline`

Daily posture snapshots with trend, current value, and annotated events.

- **Auth:** any authenticated user
- **Query params:** `days` (default 90)
- **Response:** `{ snapshots, current_score, trend, events }` (from `load_timeline` + `posture_events`)

---

### `GET /api/posture/normalized`

Normalized metrics that improve as findings are remediated.

- **Auth:** any authenticated user
- **Response:** `{ pct_critical_closed_in_7d, open_findings_per_asset, total_critical, closed_critical, fast_closed_critical }`

---

### `GET /api/posture/report.pdf`

Board-ready executive PDF of the posture timeline.

- **Auth:** any authenticated user
- **Query params:** `days` (default 90, max 365)
- **Response:** `application/pdf` file download

---

### `POST /api/posture/report/send`

Email the board report PDF to every email integration opted into board reports.

- **Auth:** admin
- **Query params:** `days` (default 90)
- **Response:** `{ ok: true, sent }` (number of integrations emailed)

---

## Error responses

All errors follow the standard FastAPI/Pydantic shape:

```json
{
  "detail": "human-readable error message"
}
```

| Status | Meaning |
|--------|---------|
| 400 | Bad request (validation error, business-rule violation) |
| 401 | Missing or invalid credentials |
| 403 | Valid credentials but insufficient role, or password change required |
| 404 | Resource not found (or not owned by the caller's org) |
| 409 | Conflict (duplicate resource) |
| 502 | Upstream service error (e.g. Jira unreachable) |
