# ── GCP project ────────────────────────────────────────────────────────────────

variable "project_id" {
  type        = string
  description = "GCP project ID where Horus will be deployed."
}

variable "region" {
  type        = string
  default     = "us-central1"
  description = "GCP region for Cloud Run and Artifact Registry."
}

# ── App ────────────────────────────────────────────────────────────────────────

variable "app_name" {
  type        = string
  default     = "horus"
  description = "Name prefix used for all GCP resources."
}

# ── GitHub (Workload Identity Federation) ──────────────────────────────────────

variable "github_org" {
  type        = string
  description = "GitHub organization or user that owns the repo (e.g. HorusAgentsSec)."
}

variable "github_repo" {
  type        = string
  default     = "horus"
  description = "GitHub repository name (e.g. horus)."
}

# ── Cloud Run scaling ──────────────────────────────────────────────────────────

variable "min_instances" {
  type        = number
  default     = 0
  description = "Minimum Cloud Run instances (0 = scale to zero when idle)."
}

variable "max_instances" {
  type        = number
  default     = 10
  description = "Maximum Cloud Run instances."
}

variable "cpu" {
  type        = string
  default     = "2"
  description = "CPU allocated per Cloud Run instance (nmap/nuclei benefit from 2 vCPUs)."
}

variable "memory" {
  type        = string
  default     = "2Gi"
  description = "Memory allocated per Cloud Run instance."
}

# ── Supabase ───────────────────────────────────────────────────────────────────

variable "supabase_url" {
  type        = string
  sensitive   = true
  description = "Supabase project URL (https://xxxx.supabase.co)."
}

variable "supabase_anon_key" {
  type        = string
  sensitive   = true
  description = "Supabase anonymous/public key."
}

variable "supabase_service_role_key" {
  type        = string
  sensitive   = true
  description = "Supabase service role key (server-side only, never exposed to the browser)."
}

# ── LLM ───────────────────────────────────────────────────────────────────────

variable "llm_base_url" {
  type        = string
  default     = "https://openrouter.ai/api/v1"
  description = "OpenAI-compatible LLM API base URL."
}

variable "llm_api_key" {
  type        = string
  sensitive   = true
  description = "API key for the LLM provider."
}

variable "llm_default_model" {
  type        = string
  default     = "anthropic/claude-opus-4-5"
  description = "Default model identifier sent to the LLM API."
}

# ── App secrets ────────────────────────────────────────────────────────────────

variable "secret_key" {
  type        = string
  sensitive   = true
  description = "Random secret for signing sessions / tokens. Generate with: openssl rand -hex 32"
}

# ── Optional integrations ──────────────────────────────────────────────────────

variable "shodan_api_key" {
  type        = string
  sensitive   = true
  default     = ""
  description = "Shodan API key for enriched asset discovery (optional)."
}

variable "breach_directory_api_key" {
  type        = string
  sensitive   = true
  default     = ""
  description = "BreachDirectory API key for credential exposure checks (optional)."
}

# ── SMTP ───────────────────────────────────────────────────────────────────────

variable "smtp_host" {
  type        = string
  default     = ""
  description = "SMTP host for email notifications (optional)."
}

variable "smtp_port" {
  type        = number
  default     = 587
  description = "SMTP port."
}

variable "smtp_user" {
  type        = string
  default     = ""
  description = "SMTP username."
}

variable "smtp_password" {
  type        = string
  sensitive   = true
  default     = ""
  description = "SMTP password."
}

variable "smtp_from" {
  type        = string
  default     = ""
  description = "From address for outgoing emails."
}

# ── Redis (optional) ───────────────────────────────────────────────────────────

variable "redis_url" {
  type        = string
  sensitive   = true
  default     = ""
  description = "Redis URL for shared rate-limit state across instances. Leave empty to use per-instance in-memory limiting."
}
