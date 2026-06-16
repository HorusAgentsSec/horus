terraform {
  required_version = ">= 1.7"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }

  # Remote state in GCS — create the bucket once manually before running terraform init:
  #   gcloud storage buckets create gs://<your-project-id>-tf-state --location=<region>
  # Then uncomment and fill in the block below, or keep local state for a quick start.
  #
  # backend "gcs" {
  #   bucket = "<your-project-id>-tf-state"
  #   prefix = "horus/state"
  # }
}

provider "google" {
  project = var.project_id
  region  = var.region
}
