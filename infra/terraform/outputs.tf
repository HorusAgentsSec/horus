output "cloud_run_url" {
  description = "Public URL of the Horus Cloud Run service."
  value       = google_cloud_run_v2_service.horus.uri
}

output "artifact_registry_repo" {
  description = "Full Artifact Registry path for Docker images."
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${var.app_name}/${var.app_name}"
}

output "wif_provider" {
  description = "Workload Identity Provider resource name — set as GH secret WIF_PROVIDER."
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "wif_service_account" {
  description = "CI/CD service account email — set as GH secret WIF_SERVICE_ACCOUNT."
  value       = google_service_account.cicd.email
}
