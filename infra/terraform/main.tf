# ── Enable required GCP APIs ───────────────────────────────────────────────────

resource "google_project_service" "apis" {
  for_each = toset([
    "run.googleapis.com",
    "artifactregistry.googleapis.com",
    "secretmanager.googleapis.com",
    "iam.googleapis.com",
    "iamcredentials.googleapis.com",
    "cloudresourcemanager.googleapis.com",
  ])
  service            = each.key
  disable_on_destroy = false
}

# ── Artifact Registry (Docker image store) ─────────────────────────────────────

resource "google_artifact_registry_repository" "horus" {
  location      = var.region
  repository_id = var.app_name
  format        = "DOCKER"
  description   = "Horus container images"
  depends_on    = [google_project_service.apis]
}

# ── Service account for Cloud Run ──────────────────────────────────────────────

resource "google_service_account" "cloud_run" {
  account_id   = "${var.app_name}-run"
  display_name = "Horus Cloud Run"
  description  = "Identity assumed by the running Horus container."
}

resource "google_project_iam_member" "run_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${google_service_account.cloud_run.email}"
}

# ── Workload Identity Federation for GitHub Actions ────────────────────────────
# No long-lived service account keys — GitHub's OIDC token is exchanged for a
# short-lived GCP credential at deploy time.

resource "google_iam_workload_identity_pool" "github" {
  workload_identity_pool_id = "${var.app_name}-github"
  display_name              = "GitHub Actions — ${var.app_name}"
  depends_on                = [google_project_service.apis]
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.github.workload_identity_pool_id
  workload_identity_pool_provider_id = "github-provider"

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }

  attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.actor"      = "assertion.actor"
    "attribute.repository" = "assertion.repository"
  }

  # Only allow tokens issued for this specific repository.
  attribute_condition = "assertion.repository == '${var.github_org}/${var.github_repo}'"
}

# ── Service account for CI/CD ──────────────────────────────────────────────────

resource "google_service_account" "cicd" {
  account_id   = "${var.app_name}-cicd"
  display_name = "Horus CI/CD"
  description  = "Used by GitHub Actions to build, push, and deploy."
}

resource "google_service_account_iam_binding" "cicd_wif" {
  service_account_id = google_service_account.cicd.name
  role               = "roles/iam.workloadIdentityUser"
  members = [
    "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.github.name}/attribute.repository/${var.github_org}/${var.github_repo}"
  ]
}

resource "google_project_iam_member" "cicd_run_admin" {
  project = var.project_id
  role    = "roles/run.admin"
  member  = "serviceAccount:${google_service_account.cicd.email}"
}

resource "google_project_iam_member" "cicd_ar_writer" {
  project = var.project_id
  role    = "roles/artifactregistry.writer"
  member  = "serviceAccount:${google_service_account.cicd.email}"
}

resource "google_project_iam_member" "cicd_sa_user" {
  project = var.project_id
  role    = "roles/iam.serviceAccountUser"
  member  = "serviceAccount:${google_service_account.cicd.email}"
}

# ── Secret Manager secrets ─────────────────────────────────────────────────────

locals {
  secrets = {
    supabase-url              = var.supabase_url
    supabase-anon-key         = var.supabase_anon_key
    supabase-service-role-key = var.supabase_service_role_key
    llm-api-key               = var.llm_api_key
    secret-key                = var.secret_key
    shodan-api-key            = var.shodan_api_key
    breach-directory-api-key  = var.breach_directory_api_key
    smtp-password             = var.smtp_password
    redis-url                 = var.redis_url
  }
}

resource "google_secret_manager_secret" "app" {
  for_each  = local.secrets
  secret_id = "${var.app_name}-${each.key}"
  replication { auto {} }
  depends_on = [google_project_service.apis]
}

resource "google_secret_manager_secret_version" "app" {
  for_each    = local.secrets
  secret      = google_secret_manager_secret.app[each.key].id
  secret_data = each.value == "" ? "UNSET" : each.value
}

# ── Cloud Run service ──────────────────────────────────────────────────────────

locals {
  image = "${var.region}-docker.pkg.dev/${var.project_id}/${var.app_name}/${var.app_name}:latest"
}

resource "google_cloud_run_v2_service" "horus" {
  name     = var.app_name
  location = var.region

  template {
    service_account = google_service_account.cloud_run.email

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    # Nuclei template updates and nmap scans can take several minutes.
    timeout = "3600s"

    containers {
      image = local.image

      resources {
        limits = {
          cpu    = var.cpu
          memory = var.memory
        }
        # Allow CPU bursting during scan runs.
        cpu_idle = false
      }

      ports {
        container_port = 8000
      }

      # ── Non-sensitive env vars ────────────────────────────────────────────────
      env { name = "ENVIRONMENT";             value = "production" }
      env { name = "LLM_BASE_URL";            value = var.llm_base_url }
      env { name = "LLM_DEFAULT_MODEL";       value = var.llm_default_model }
      env { name = "SMTP_HOST";               value = var.smtp_host }
      env { name = "SMTP_PORT";               value = tostring(var.smtp_port) }
      env { name = "SMTP_USER";               value = var.smtp_user }
      env { name = "SMTP_FROM";               value = var.smtp_from }
      env { name = "SMTP_USE_TLS";            value = "true" }
      env { name = "TRUST_PROXY_HEADERS";     value = "true" }
      env { name = "RATE_LIMIT_ENABLED";      value = "true" }
      env { name = "REDACTION_ENABLED";       value = "true" }
      env { name = "LLM_ENABLED";             value = "true" }
      env { name = "ANALYST_TEAM_ENABLED";    value = "true" }
      env { name = "VALIDATION_ENABLED";      value = "true" }
      env { name = "PIPELINE_MAX_CONCURRENCY"; value = "2" }

      # ── Secrets from Secret Manager ───────────────────────────────────────────
      dynamic "env" {
        for_each = {
          SUPABASE_URL              = "supabase-url"
          SUPABASE_ANON_KEY         = "supabase-anon-key"
          SUPABASE_SERVICE_ROLE_KEY = "supabase-service-role-key"
          LLM_API_KEY               = "llm-api-key"
          SECRET_KEY                = "secret-key"
          SHODAN_API_KEY            = "shodan-api-key"
          BREACH_DIRECTORY_API_KEY  = "breach-directory-api-key"
          SMTP_PASSWORD             = "smtp-password"
          REDIS_URL                 = "redis-url"
        }
        content {
          name = env.key
          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.app[env.value].secret_id
              version = "latest"
            }
          }
        }
      }
    }
  }

  depends_on = [
    google_artifact_registry_repository.horus,
    google_project_iam_member.run_secret_accessor,
    google_secret_manager_secret_version.app,
  ]

  lifecycle {
    # The CI/CD pipeline updates the image tag on every deploy.
    # Ignore it here so terraform plan stays clean between deploys.
    ignore_changes = [
      template[0].containers[0].image,
      template[0].revision,
      client,
      client_version,
    ]
  }
}

# ── Make the service publicly accessible ───────────────────────────────────────

resource "google_cloud_run_v2_service_iam_member" "public_invoker" {
  project  = google_cloud_run_v2_service.horus.project
  location = google_cloud_run_v2_service.horus.location
  name     = google_cloud_run_v2_service.horus.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
