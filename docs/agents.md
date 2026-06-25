# Agent Pipeline

The Horus agent pipeline is the AI backbone that turns raw scanner output into actionable,
prioritized security findings. Every time a scan runs — whether triggered by a user, a
schedule, or the Iris host-monitoring triage — it passes through a fixed sequence of agents
and deterministic steps. Each step mutates and returns a shared `ScanState` object; later steps
see everything earlier ones produced.

The pipeline also includes two out-of-band agents (Red and Blue) that run at org scope rather
than per-scan, and a separate host-event triage path (Iris) for endpoint monitoring.

---

## 1. When the pipeline runs

**On-demand scans.** `POST /api/scans` creates a scan row in Supabase with `status: pending` and
enqueues it via `submit_scan`. A bounded worker pool picks it up and calls
`run_pipeline_for_scan(scan_id, org_id)`.

**Scheduled scans.** APScheduler calls `run_pipeline_for_schedule(schedule_id)`, which inserts
one scan row per asset and enqueues them the same way. Scheduled scans auto-retry on failure.

**Iris AI triage.** `run_iris_triage_for_org` runs on a per-org interval (default: 60 min).
When the LLM flags a group of host events as HIGH or CRITICAL risk, it triggers the full
pipeline for the affected agent's asset via `_do_process_agent`.

Before starting, `run_pipeline_for_scan` calls `check_budget(org_id)`. If any configured
daily/weekly/monthly token limit is exceeded the scan is immediately marked `failed` and the
pipeline does not execute.

---

## 2. Pipeline stages

```
[API / Scheduler / Iris Triage]
           |
           v
     run_pipeline_for_scan
           |
           v
   +-----------------+
   |    run_recon     |   (no LLM: Nmap + Nuclei subprocesses)
   +-----------------+
           |
           v
   +-----------------+
   |  AnalystAgent    |   (LLM: classifies findings; parallel domain specialists)
   +-----------------+
           |
           v
   +--------------------+
   |  run_correlation   |   (no LLM: CPE->CVE via NVD)
   +--------------------+
           |
           v
   +--------------------+
   |  run_threat_intel  |   (no LLM: KEV + EPSS lookup)  <-- live flush to DB
   +--------------------+
           |
           v
   +--------------------+
   |  ValidationAgent   |   (LLM: red/blue adversarial debate)  <-- live flush to DB
   +--------------------+
           |
           v
   +---------------------+
   |  RemediationAgent   |   (LLM: concrete fix suggestions)
   +---------------------+
           |
           v
   +--------------------+
   |  run_risk_manager  |   (no LLM: SSVC + permission rules)
   +--------------------+
           |
           v
   +-----------------+
   |  ReporterAgent   |   (LLM: executive summary)
   +-----------------+
           |
           v
      _persist_results
      (upsert findings, suggestions, report to Supabase)
```

The pipeline is sequential. A failure in one step is logged and the run continues rather than
aborting. Cancellation is polled before and after every step: if the scan row transitions to
`canceled` the pipeline stops immediately and returns.

Two intermediate flushes happen during the run (`STREAM_AFTER = {"threat_intel", "validation"}`).
These upsert findings to Supabase so the UI populates in real time before the slower tail
(remediation, report) completes. The final `_persist_results` is the authoritative write.

---

## 3. Agents

### run_recon

The only step that touches the network directly. Runs Nmap against every asset type; adds
Nuclei for `web`, `api`, and `domain` assets. Before launching any subprocess it calls
`validate_scan_target` to reject RFC-1918 ranges, loopback, cloud metadata endpoints, and other
unsafe targets (defense-in-depth over the asset creation gate).

**Input:** `ScanState` with `asset` populated.
**Output:** `state.raw_findings` (list of `RawFinding`) and `state.detected_services` (product/version
per open port, used downstream by CorrelationAgent).
**LLM calls:** 0.

### AnalystAgent

Classifies raw scanner findings: assigns a human-readable title, one-sentence description,
severity, CVSS score (if determinable), confidence (0-1), and a deterministic SHA-256 fingerprint
keyed on `asset_id:tool:template_id`.

When `analyst_team_enabled` is true and findings span more than one domain, it fans out to
parallel `SpecialistAnalyst` instances (up to 4 threads). Each specialist is pre-primed with a
domain-specific system prompt:

- `web`: HTTP, API, injection, XSS, CORS, auth bypass.
- `network`: exposed ports, legacy protocols, unauthenticated services.
- `tls`: certificate validity, cipher weaknesses, protocol downgrades.
- `generic`: catch-all for anything that doesn't match the keyword routers.

Domain routing (`classify_domain`) is a pure keyword function over `tool + template_id + name`
and is unit-tested. When the LLM is disabled (`llm_enabled = false`) the agent falls back to a
deterministic classifier that trusts the scanner's own severity with confidence 0.5.

**Input:** `state.raw_findings`.
**Output:** `state.analyzed_findings` (list of `AnalyzedFinding`).
**LLM calls:** 1 per domain group (parallel). 0 in no-cloud mode.

### run_correlation

A purely deterministic step that turns detected software versions into CVE findings via the NVD.
It calls `correlate_services` (CPE matching from `cpe_intel`) to map each `product/version` to a
set of CVE IDs, then deduplicates against CVEs already reported by the scanners (both as
structured `cve_ids` on analyzed findings and as raw text in Nmap `vulners` output). New CVEs are
looked up in the local `cve_intel` table for CVSS severity; each becomes an `AnalyzedFinding`
with `source_service` set to the matched software label (used to group them in the UI).

Confidence is fixed at 0.7 because version-based correlation is weaker than an active probe: the
package may have been patched without a version bump.

**Input:** `state.detected_services`, `state.analyzed_findings`.
**Output:** new entries appended to `state.analyzed_findings`.
**LLM calls:** 0.

### run_threat_intel

Enriches every analyzed finding with KEV and EPSS data from the local `cve_intel` table (synced
daily from CISA and FIRST). For each finding it selects the most threatening CVE (KEV takes
precedence over EPSS) and derives an exploitability label:

| Signal | Label |
|---|---|
| In CISA KEV | `active` |
| EPSS >= 0.50 | `high` |
| EPSS >= 0.10 | `medium` |
| EPSS > 0 | `low` |
| No match | `none` |

A human-readable `threat_context` string is generated deterministically from the row data
(KEV date, ransomware flag, EPSS percentile).

**Input:** `state.analyzed_findings`.
**Output:** `state.enriched_findings` (list of `EnrichedFinding`).
**LLM calls:** 0.

After this step the pipeline flushes findings to Supabase (first live stream).

### ValidationAgent

The adversarial debate layer. Its goal is to eliminate false positives before remediation
spending and before the report is written.

For each finding it applies a tiered resolution strategy (cheapest first):

1. **KEV-active auto-confirm.** Actively exploited in the wild: verdict is `confirmed`, no
   debate needed.
2. **Org memory.** A teammate already judged a finding with this signature. Repeat the prior and
   skip the debate.
3. **Community memory.** Cross-org anonymized aggregate has a strong consensus. Applied unless
   the finding is exploitable and internet-facing (too risky to silence without local review).
4. **Deterministic triage** (`validation.auto_verdict`). Clear-cut cases resolved by rules
   (e.g., `info` severity is noise; confirmed scanner hit with high confidence is real).
5. **Active probe** (opt-in). For version-only correlation findings, connects to the live
   service port to verify the service is still running and matches. Confirmed or refuted
   deterministically; inconclusive falls through.
6. **LLM debate.** Genuinely ambiguous findings go through the red/blue debate (see section 5).
   Capped at `validation_max_debates` per scan to bound cost.

After this step the pipeline flushes findings again (second live stream, with verdicts attached).

**Input:** `state.analyzed_findings`, `state.enriched_findings`, `state.detected_services`.
**Output:** `verdict`, `verdict_rationale`, `debate`, and updated `confidence` written back onto
each `AnalyzedFinding` in place.
**LLM calls:** 0-N (one per debated finding, up to the cap). 0 in no-cloud mode.

### RemediationAgent

Generates concrete, step-by-step remediation suggestions for every non-false-positive finding.
False positives are excluded: no point paying for a fix for something the debate ruled out.

The prompt includes asset context (internal vs. external, tags) so suggestions are
environment-appropriate. For each finding it outputs an `action_type` (e.g.,
`update_library`, `patch_config`, `rotate_credentials`), a title, numbered steps, an optional
shell command or config snippet, an `estimated_risk` for the fix itself, and a confidence score.

**Input:** `state.analyzed_findings` (excluding `false_positive`), `state.enriched_findings`.
**Output:** `state.remediation_suggestions` (list of `RemediationSuggestion`).
**LLM calls:** 1 (batch). Skipped entirely in no-cloud mode.

### run_risk_manager

Assigns an execution mode to each remediation suggestion. This is deterministic throughout.

Permission rules (from `permission_policies`) are evaluated first in order; the first matching
rule wins. If no rule matches, SSVC deployer priority drives the decision:

| SSVC priority | Default mode |
|---|---|
| Act | `auto` |
| Attend | `approval_required` |
| Track / Track* | `suggest_only` |

A hard safety ceiling is applied last: the fix's `safety_tier` (reversible / disruptive /
destructive) clamps the mode downward regardless of what the rule or SSVC asked for. A
`destructive` fix can never be `auto`, for example.

**Input:** `state.remediation_suggestions`, `state.analyzed_findings`, `state.enriched_findings`,
`state.permission_rules`.
**Output:** `state.risk_decisions` (list of `RiskDecision`).
**LLM calls:** 0.

### ReporterAgent

Writes the executive scan report. It excludes false positives and orders the top 10 findings
by SSVC urgency first, then by severity, so the "act now" items lead. The LLM is given severity
counts and the SSVC-ordered top findings; it returns a 2-3 sentence executive summary plus
concrete next steps.

In no-cloud mode the report is assembled deterministically from the same counts and ordering,
leading with `Act`/`Attend` items and falling back to "keep monitoring" if none exist.

**Input:** `state.analyzed_findings`, `state.enriched_findings`.
**Output:** `state.report` (`ScanReport`).
**LLM calls:** 1. 0 in no-cloud mode.

---

## 4. Out-of-band agents

These agents do not sit in the per-scan pipeline sequence. They run at org scope on demand.

### RedAgent

An adversarial recon agent that thinks like an external attacker. It uses a tool-calling loop
(via `ToolAgent`) to probe attack surface that automated scanners typically miss:

- DNS email-security checks (SPF, DMARC, DKIM, zone transfer via `check_dns_security`)
- Exposed sensitive paths (`.env`, `.git`, admin panels via `check_exposed_paths`)
- Security response headers (`check_security_headers`)
- TLS certificate and cipher weaknesses (`check_ssl_tls`)
- Subdomain discovery via Certificate Transparency logs (`enumerate_subdomains`)
- Public exploit availability for known CVEs (`lookup_exploits`)
- Credential breach exposure (`hibp_domain_check`)
- General threat intelligence (`web_search`)

The model decides which tools to call, in what order, and when to stop (up to `max_iterations=20`
per run). It saves only genuine findings (with a concrete `attack_scenario`) via `save_red_finding`.
Org-level token budget is checked between iterations.

**Trigger:** `POST /api/agents/red/run` (org scope, not per-scan).

### BlueAgent

The defensive counterpart. It reads open `red_findings` for the org, researches each one using
the same tool-calling loop, and writes a structured remediation response back to the database.
For each finding it looks up CVE details, checks exploit availability, and searches the web for
the current vendor advisory or hardening guide, then calls `respond_to_finding` with a root-cause
explanation, ordered remediation steps, a verification command, effort estimate, and reference
URLs.

**Trigger:** `POST /api/agents/blue/run` (org scope, typically after a Red Agent run).

### PhishingAgent

Generates context-aware phishing simulation emails for internal security awareness campaigns.
Unlike generic phishing tools it receives the org's real asset inventory (subdomains, detected
technologies) so lures can reference live internal systems. Supports both one-off personalized
emails and reusable templates with `{{employee_name}}` / `{{tracking_url}}` placeholders.
Never used offensively; all output is for authorized internal simulation only.

---

## 5. Adversarial debate (ValidationAgent detail)

For genuinely ambiguous findings that survive the deterministic triage the ValidationAgent calls
the LLM as a two-person panel plus judge. The prompt forces both positions in writing before a
verdict is issued:

```
red:     strongest case that this is a REAL, reachable, exploitable finding.
blue:    strongest case this is a false positive — not reachable, version-only guess,
         or already mitigated.
verdict: confirmed | likely | needs_verification | false_positive
confidence: 0.0-1.0
rationale: one sentence justifying the verdict.
```

The model is explicitly instructed to treat version-banner-only matches and Nmap
`http-csrf`/`http-*-xss` "potential" scripts as weak signals unless corroborated by other
evidence. Forcing the skeptical case in writing before the ruling is the debiasing mechanism
that prevents inflated confidence on speculative matches.

The structured output (`verdict`, `confidence`, `rationale`, plus both advocate arguments) is
stored on the finding and surfaced in the UI under each agent run's `output_state.debates`
field. This makes the pipeline's reasoning inspectable.

**Cost controls on the debate:**

- A per-scan cap (`validation_max_debates`) limits how many findings can enter the LLM path.
  Findings past the cap receive `needs_verification` deterministically.
- KEV-active findings skip the debate entirely (always `confirmed`).
- Org and community memory short-circuit repeated debates for signature-matched findings.
- Active probing (opt-in) resolves version-only findings before the LLM is called.
- The debate prompt targets 512 max tokens per call.

After the verdict, `verdict_memory.record` stores the outcome so future scans can skip the
debate for the same signature.

---

## 6. State object

`ScanState` is a Pydantic model. The pipeline passes it by value through each step; each agent
receives the previous agent's output as its input.

| Field | Type | Set by |
|---|---|---|
| `scan_id` | `str` | pipeline entry point |
| `org_id` | `str` | pipeline entry point |
| `asset` | `AssetInfo` | pipeline entry point |
| `permission_rules` | `list[dict]` | pipeline entry point (from `permission_policies`) |
| `raw_findings` | `list[RawFinding]` | `run_recon` |
| `detected_services` | `list[dict]` | `run_recon` |
| `analyzed_findings` | `list[AnalyzedFinding]` | `AnalystAgent` + `run_correlation`; mutated by `ValidationAgent` |
| `enriched_findings` | `list[EnrichedFinding]` | `run_threat_intel` |
| `remediation_suggestions` | `list[RemediationSuggestion]` | `RemediationAgent` |
| `risk_decisions` | `list[RiskDecision]` | `run_risk_manager` |
| `report` | `ScanReport \| None` | `ReporterAgent` |
| `errors` | `list[str]` | any agent on failure |
| `canceled` | `bool` | pipeline loop on cancellation check |

**Key sub-models:**

`AnalyzedFinding` is the central data object. It starts with `verdict=None` and gains
`verdict`, `verdict_rationale`, `debate`, and updated `confidence` after `ValidationAgent`.
Its `id` field is a deterministic SHA-256 fingerprint (`asset_id:tool:template_id`) used as the
upsert conflict key in Supabase so re-running a scan updates existing findings rather than
duplicating them.

`EnrichedFinding` links to an `AnalyzedFinding` by `finding_id` and carries the KEV/EPSS
signals. Agents that need exploitability data (ValidationAgent, RemediationAgent, ReporterAgent)
build an `{id: EnrichedFinding}` index to avoid O(n²) lookups.

`RiskDecision` links to a `RemediationSuggestion` by `suggestion_id` and stores the execution
mode, SSVC breakdown, and safety tier. The mode flows into `agent_suggestions.mode` in Supabase.

---

## 7. Token budget management

Token limits are set per-org in `org_settings` as `token_limit_daily`, `token_limit_weekly`, and
`token_limit_monthly`. Any or all can be set independently; an org with only a monthly limit is
only checked monthly.

`check_budget(org_id)` queries `agent_runs` for token sums across the relevant windows. Results
are cached per-org for 5 minutes to avoid a DB round-trip on every agent step. It returns
`{"ok": True}` on any DB error (fail-open to avoid blocking scans on transient network issues).

Budget is checked at three points:

1. **Before the scan pipeline starts** (`run_pipeline_for_scan`). Exceeded budget marks the scan
   `failed` immediately.
2. **Between iterations of tool-calling agents** (`ToolAgent.run_with_tools`). RedAgent and
   BlueAgent check after each tool loop iteration so a long-running session cannot drain the
   budget past the limit.
3. **Before Iris triage LLM calls** (`run_iris_triage_for_org`). Host-event analysis is skipped
   if budget is exceeded.

At 80% utilization, org admins receive an in-app notification. At 100% a second notification is
sent and the budget is blocked.

Each agent records `tokens_used` and `model_used` on its `agent_runs` row, which is the source
of truth for the budget calculation and for the per-scan pipeline transparency view.

---

## 8. Iris AI triage

Iris is the host monitoring subsystem. Its triage path is distinct from the per-scan pipeline
but feeds into it.

`run_iris_triage_for_org` runs on a configurable interval (default: 60 min). It fetches up to
2,000 unprocessed `iris_events`, groups them by `(event_type, severity)`, and sends a compact
summary to the LLM (titles only, no raw payloads). The prompt budget is roughly 200-400 input
tokens regardless of event volume.

The LLM returns a JSON array identifying groups with `CRITICAL` or `HIGH` risk and a one-sentence
reason. For each flagged group a triage finding is inserted, and `_do_process_agent` triggers the
full Horus scan pipeline for the affected asset.

Known-false-positive groups (via org and community verdict memory) are filtered out before the
LLM call to avoid re-analyzing noise the team has already dismissed.

`detect_offline_agents` runs separately to catch agents that stopped reporting: it flips their
status and creates a `medium`-severity finding exactly once per transition.

---

## 9. Triggering the pipeline manually

**Trigger a single scan:**

```http
POST /api/scans
Authorization: Bearer <token>
Content-Type: application/json

{
  "asset_id": "<asset-uuid>",
  "tools": ["nuclei", "nmap"]
}
```

Returns `{"scan_id": "<uuid>", "status": "pending"}` (HTTP 202). Requires the `analyst` role.

**Trigger scans for all assets in the org:**

```http
POST /api/scans/scan-all
Authorization: Bearer <token>
```

**Cancel all active scans:**

```http
POST /api/scans/cancel-active
Authorization: Bearer <token>
```

**Cancel a specific scan:**

```http
POST /api/scans/{scan_id}/cancel
Authorization: Bearer <token>
```

**Trigger Red Agent:**

```http
POST /api/agents/red/run
Authorization: Bearer <token>
```

**Trigger Blue Agent (respond to open red findings):**

```http
POST /api/agents/blue/run
Authorization: Bearer <token>
```

For local development, `run_pipeline_for_scan(scan_id, org_id)` in
`backend/agents/pipeline.py` can be called directly from a Python shell or test fixture. The
function is synchronous and returns the final `ScanState`.

---

## 10. LLM provider configuration

All agents share a single OpenAI-compatible client (`BaseAgent._client`). The provider is
configured via environment variables:

| Variable | Purpose |
|---|---|
| `LLM_BASE_URL` | Provider base URL (e.g., `https://openrouter.ai/api/v1`) |
| `LLM_API_KEY` | API key |
| `LLM_DEFAULT_MODEL` | Fallback model for all agents |
| `LLM_ANALYST_MODEL` | Override model for AnalystAgent |
| `LLM_VALIDATION_MODEL` | Override model for ValidationAgent |
| `IRIS_TRIAGE_MODEL` | Override model for Iris triage |

Per-agent model overrides follow the pattern `LLM_<AGENT_TYPE>_MODEL`. Any OpenAI-compatible
endpoint works, including Ollama for fully local/offline operation.

When `LLM_ENABLED=false` the LLM-dependent agents (Analyst, Validation, Remediation, Reporter)
fall back to deterministic implementations. Recon, Correlation, ThreatIntel, and RiskManager are
unaffected because they never call an LLM.

**Prompt privacy.** When `REDACTION_ENABLED=true`, a per-run `Redactor` is attached to each
agent. It pseudonymizes `user_content` (hostnames, IPs, org-identifying strings) before any
LLM call and restores real values in the response before downstream use or persistence.
