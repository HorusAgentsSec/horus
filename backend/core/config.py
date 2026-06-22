from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # Supabase
    supabase_url: str
    supabase_anon_key: str
    supabase_service_role_key: str

    # LLM provider — OpenAI-compatible endpoint
    # OpenRouter: https://openrouter.ai/api/v1
    # Ollama:     http://localhost:11434/v1
    # Anthropic (via OpenRouter): https://openrouter.ai/api/v1
    llm_base_url: str = "https://openrouter.ai/api/v1"
    llm_api_key: str = ""

    # Default model — any model string accepted by your provider
    # OpenRouter examples: "anthropic/claude-opus-4-5", "openai/gpt-4o", "meta-llama/llama-3.1-70b-instruct"
    # Ollama examples:     "llama3.1:70b", "qwen2.5-coder:32b", "mistral:latest"
    llm_default_model: str = "anthropic/claude-opus-4-5"

    # LLM call robustness — bound each request so a hung provider can't stall a
    # pipeline worker indefinitely. max_retries covers transient/network errors.
    llm_timeout_seconds: float = 60.0
    llm_max_retries: int = 2

    # Per-agent model overrides (optional — falls back to llm_default_model)
    llm_analyst_model: Optional[str] = None
    llm_threat_intel_model: Optional[str] = None
    llm_validation_model: Optional[str] = None
    llm_remediation_model: Optional[str] = None
    llm_risk_manager_model: Optional[str] = None
    llm_reporter_model: Optional[str] = None

    # ── Data privacy ─────────────────────────────────────────────────────────
    # Pseudonymize sensitive identifiers (hostnames, IPs, emails) in every prompt before it leaves
    # the process for a cloud LLM, restoring them in the response. On by default — privacy by design;
    # a deployment wanting maximum model fidelity (or running a fully local model) can turn it off.
    redaction_enabled: bool = True
    # Master switch for the LLM agents. False = fully deterministic "no-cloud" mode: the whole
    # pipeline runs with ZERO LLM calls (rule-based analyst, auto-only validation, no remediation
    # drafting, templated report). The deterministic core (CVE correlation, SSVC, posture, Watchtower)
    # is unaffected. For air-gapped / maximum-privacy deployments where no data may leave the perimeter.
    llm_enabled: bool = True

    # ── Community verdicts (cross-customer false-positive flywheel) ──────────
    # Aggregate per-org verdict feedback across the fleet (anonymized, k-anonymity enforced in the DB
    # function) so a new org benefits from what everyone has learned. A daily job recomputes it.
    community_verdicts_enabled: bool = True
    community_verdicts_cron: str = "0 4 * * *"  # daily 04:00, before the KEV sync/watchtower chain

    # ── Analyst team (parallel domain specialists) ───────────────────────────
    # Route each raw finding to a domain specialist (web / network / TLS) and run them in parallel
    # for sharper, lower-latency analysis. Off → a single generalist analyst call.
    analyst_team_enabled: bool = True

    # ── Finding validation (red/blue adversarial debate) ─────────────────────
    # The debate calibrates confidence and catches false positives. Deterministic triage resolves
    # the obvious findings for free; only ambiguous ones reach the LLM, capped per scan to bound cost.
    validation_enabled: bool = True
    validation_max_debates: int = 15
    # Active validation: confirm a version-only finding against the live service (one cheap,
    # non-destructive connection) before debating it. Off by default — it touches the network.
    active_validation_enabled: bool = False
    active_validation_timeout: float = 3.0

    # Maintenance (blackout) windows: scheduled scans/discovery that land inside a window are
    # skipped (not queued for later). Comma-separated "[DAYS ]HH:MM-HH:MM" specs, e.g.
    # "Mon-Fri 09:00-18:00, Sat,Sun 00:00-23:59". Empty = never blacked out.
    scan_blackout_windows: str = ""
    # IANA timezone the blackout windows are expressed in (e.g. "Europe/Madrid"). Empty = the
    # server's local timezone. Set this on a UTC deploy (fly.io) so "business hours" windows
    # mean the operator's local hours, not UTC.
    scan_blackout_timezone: str = ""

    # App
    environment: str = "development"
    secret_key: str = "changeme"

    # Scan pipeline — bounded worker pool so concurrent scans can't exhaust
    # resources or hammer the LLM provider. Scans queue beyond this limit.
    pipeline_max_concurrency: int = 2
    # Auto-retry for *scheduled* scans that fail (e.g. a transient LLM/provider hiccup), so an
    # unattended schedule self-heals. User-triggered scans don't auto-retry (the user can re-run).
    scan_max_retries: int = 1

    # Rate limiting (in-memory, per-process). See backend/core/rate_limit.py.
    rate_limit_enabled: bool = True
    rate_limit_per_minute: int = 120          # per-IP, all /api routes
    rate_limit_sensitive_per_minute: int = 10  # per-IP, write-heavy endpoints
    # Honor X-Forwarded-For only behind a trusted reverse proxy (else it is spoofable).
    trust_proxy_headers: bool = False
    # Optional Redis URL for shared rate-limit state across workers.
    # When unset, falls back to per-process in-memory sliding window.
    # Example: redis://localhost:6379/0  or  redis://:password@redis-host:6379/0
    redis_url: str | None = None

    # ── CVE intelligence sync (CISA KEV + FIRST EPSS) ────────────────────────
    # Global reference data synced into the cve_intel table by a daily job.
    # URLs are configurable because upstream hosting moves occasionally.
    cve_sync_enabled: bool = True
    cve_sync_cron: str = "0 5 * * *"  # daily 05:00 (after KEV/EPSS publish)
    kev_feed_url: str = (
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    )
    # FIRST EPSS daily scores (gzipped CSV). If this 404s, check epss.empiricalsecurity.com.
    epss_feed_url: str = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
    # Storing all ~250k EPSS rows is heavy; skip in dev to sync only KEV (small, high-signal).
    cve_sync_include_epss: bool = True
    cve_sync_batch_size: int = 1000  # rows per upsert request
    cve_sync_timeout_seconds: float = 120.0

    # ── CPE -> CVE correlation (NVD, on-demand + cache) ──────────────────────
    nvd_api_base: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    # Optional NVD API key — raises the rate limit from 5 to 50 req/30s. Get one
    # free at https://nvd.nist.gov/developers/request-an-api-key
    nvd_api_key: Optional[str] = None
    nvd_timeout_seconds: float = 30.0
    # Min seconds between NVD requests (5 req/30s without key → 6s; ~0.6s with key).
    nvd_min_interval_seconds: float = 6.0
    # How long a cached CPE->CVE answer stays fresh before we re-query NVD.
    cpe_cache_max_age_days: int = 7

    # ── Notifications (Slack + email) ────────────────────────────────────────
    # Only notify when a scan has at least one finding >= this severity (or any
    # actively-exploited / KEV finding, which always notifies). Per-integration
    # config can override this.
    notify_default_min_severity: str = "high"
    # Global SMTP fallback for email integrations that don't carry their own server
    # config. Per-integration config (smtp_host, etc.) takes precedence.
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_user: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_from: Optional[str] = None
    smtp_use_tls: bool = True

    # ── Watchtower (continuous exposure monitoring) ──────────────────────────
    # Daily, after the KEV/EPSS sync, re-correlate each asset's persisted software
    # inventory against newly known-exploited CVEs — no re-scan — and alert on new
    # exposure. This is what turns a one-off scan into recurring value.
    watchtower_enabled: bool = True
    watchtower_cron: str = "30 5 * * *"  # 30 min after the KEV/EPSS sync (cve_sync_cron)
    # A CVE counts as "newly exploited" if it entered CISA KEV within this many days.
    # Wider than 1 day so a late/missed run still catches recent additions; the
    # (asset, cve) dedup store prevents repeat alerts.
    watchtower_lookback_days: int = 3
    # EPSS-spike alerting: warn when a CVE already in the inventory sees its exploitation
    # probability jump day-over-day — an early signal, often before it reaches KEV. A spike needs
    # the new score at/above the floor AND a day-over-day rise of at least the delta.
    watchtower_epss_spike_enabled: bool = True
    watchtower_epss_floor: float = 0.5          # only alert when EPSS is at least this (≥50%)
    watchtower_epss_spike_delta: float = 0.2    # and it rose by at least this since yesterday

    # ── Posture timeline (executive risk trend) ──────────────────────────────
    # A daily per-org risk snapshot feeds the posture chart. Snapshots are also taken
    # after each scan and after Watchtower alerts; this cron covers days with no scan.
    posture_snapshot_enabled: bool = True
    posture_snapshot_cron: str = "0 6 * * *"  # after the watchtower run (watchtower_cron)
    # Monthly board report: email the posture PDF to email integrations opted in (config
    # {"posture_report": true}). Off-cycle from daily jobs so it lands as a monthly digest.
    posture_report_enabled: bool = True
    posture_report_cron: str = "0 7 1 * *"  # 07:00 on the 1st of each month
    posture_report_days: int = 90  # trend window covered by the emailed report

    # ── Asset auto-discovery (passive: CT logs + DNS) ────────────────────────
    discovery_crtsh_url: str = "https://crt.sh/"
    discovery_certspotter_url: str = "https://api.certspotter.com/v1/issuances"  # CT fallback
    discovery_timeout_seconds: float = 60.0  # crt.sh is often slow
    discovery_crtsh_retries: int = 2
    # Only auto-create hosts that resolve in DNS (CT logs are full of dead names).
    discovery_resolve_dns: bool = True
    # DNS brute-force of common subdomain labels — finds hosts that never issued a cert
    # (so CT logs miss them). Passive (DNS lookups only); confirmed by resolution.
    discovery_dns_bruteforce: bool = True
    discovery_bruteforce_concurrency: int = 12
    # Safety cap: never auto-create more than this many assets in a single run.
    discovery_max_assets_per_run: int = 200
    # Private-network discovery (active ping sweep). Refuse CIDRs larger than this many
    # addresses (a /22) so nobody kicks off a /8 sweep by accident. Public CIDRs are refused.
    discovery_network_max_hosts: int = 1024
    discovery_nmap_sweep_timeout: int = 600

    # Optional integrations
    shodan_api_key: Optional[str] = None

    # ── HaveIBeenPwned (HIBP) — credential breach monitoring ─────────────────
    # Domain Search API key — get one at https://haveibeenpwned.com/API/Key
    # Without a key the HIBP check is disabled (the endpoint requires auth).
    hibp_api_key: Optional[str] = None
    hibp_check_enabled: bool = True
    hibp_check_cron: str = "0 3 * * *"   # daily 03:00, before the CVE sync chain
    hibp_api_base: str = "https://haveibeenpwned.com/api/v3"
    hibp_timeout_seconds: float = 30.0

    # ── Red/Blue adversarial agents ─────────────────────────────────────────
    adversarial_enabled: bool = True
    adversarial_cron: str = "0 2 * * *"  # daily 02:00, before the CVE/KEV sync chain
    llm_red_model: Optional[str] = None   # override for RedAgent (falls back to llm_default_model)
    llm_blue_model: Optional[str] = None  # override for BlueAgent
    # Web search key (Tavily — https://tavily.com). If absent, search is disabled.
    tavily_api_key: Optional[str] = None
    # GitHub personal token for exploit/PoC searches. Rate-limit is 10 req/min without one.
    github_token: Optional[str] = None

    # ── Phishing simulation ──────────────────────────────────────────────────
    # Base URL used to build honeypot tracking links; should point to this server.
    phishing_base_url: str = "http://localhost:8000"
    # LLM model for the PhishingAgent (falls back to llm_default_model)
    llm_phishing_model: Optional[str] = None

    # ── Iris AI Triage ───────────────────────────────────────────────────────
    # Periodic AI analysis of host agent events. Runs every iris_triage_check_minutes
    # globally; per-org interval is configurable from the Settings page.
    iris_triage_enabled: bool = True
    iris_triage_check_minutes: int = 15   # how often the scheduler polls (global)
    iris_triage_model: Optional[str] = None  # defaults to llm_default_model
    # An online agent that stops reporting for this long is flagged offline + alerted once
    # (a monitored host going dark is a blind spot — could be a reboot or a killed agent).
    iris_offline_after_minutes: int = 10

    # ── Ransomware.live deep web intelligence ────────────────────────────────
    # Check assets against ransomware.live victim database (free API, no auth).
    ransomware_check_enabled: bool = True
    ransomware_check_cron: str = "30 6 * * *"  # 06:30 AM, after watchtower (watchtower_cron + 1h)

    # ── abuse.ch IOC feeds (ThreatFox + URLhaus) ────────────────────────────────
    # Check assets against ThreatFox and URLhaus IOC databases (free APIs, no auth).
    ioc_check_enabled: bool = True
    ioc_check_cron: str = "0 6 * * *"  # 6:00 AM, after ransomware check

    class Config:
        env_file = ".env"
        extra = "ignore"


settings = Settings()
