# Horus — Infrastructure as Code (GCP + GitHub Actions)

Single-container deployment on **Google Cloud Run** with zero long-lived secrets.
The frontend is compiled into the backend image; Supabase is the only external database.

## Architecture

```
GitHub Actions
    │  Workload Identity Federation (no static keys)
    ▼
Artifact Registry   ──►  Cloud Run (horus)
                              │
                              ├─ Secret Manager  (Supabase keys, LLM key, …)
                              └─ Supabase (external)
```

## Prerequisites

| Tool | Min version |
|------|-------------|
| [Terraform](https://developer.hashicorp.com/terraform/install) | 1.7 |
| [gcloud CLI](https://cloud.google.com/sdk/docs/install) | latest |
| A GCP project with billing enabled | — |

## First-time setup (~10 min)

### 1. Authenticate gcloud

```bash
gcloud auth login
gcloud config set project YOUR_PROJECT_ID
gcloud auth application-default login
```

### 2. (Optional) Create a GCS bucket for Terraform state

```bash
gcloud storage buckets create gs://YOUR_PROJECT_ID-tf-state \
  --location=us-central1 \
  --uniform-bucket-level-access
```

Then uncomment the `backend "gcs"` block in `terraform/providers.tf` and fill in the bucket name.

### 3. Configure Terraform variables

```bash
cd infra/terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your real values (this file is git-ignored).
```

### 4. Apply infrastructure

```bash
terraform init
terraform plan   # review before applying
terraform apply
```

Terraform will print:

```
cloud_run_url        = "https://horus-xxxx-uc.a.run.app"
artifact_registry_repo = "us-central1-docker.pkg.dev/PROJECT/horus/horus"
wif_provider         = "projects/NUMBER/locations/global/workloadIdentityPools/..."
wif_service_account  = "horus-cicd@PROJECT.iam.gserviceaccount.com"
```

### 5. Set GitHub Actions secrets

Go to **Settings → Secrets and variables → Actions** in the GitHub repo and add:

| Secret | Value |
|--------|-------|
| `GCP_PROJECT_ID` | Your GCP project ID |
| `GCP_REGION` | e.g. `us-central1` |
| `WIF_PROVIDER` | `wif_provider` output from Terraform |
| `WIF_SERVICE_ACCOUNT` | `wif_service_account` output from Terraform |
| `VITE_SUPABASE_URL` | Your Supabase project URL |
| `VITE_SUPABASE_ANON_KEY` | Your Supabase anon key |

### 6. Push to main → auto-deploy

Every push to `main` triggers `.github/workflows/deploy.yml`:
1. Builds the Docker image (backend + compiled frontend)
2. Pushes it to Artifact Registry
3. Deploys the new revision to Cloud Run with zero downtime

Pull requests trigger `.github/workflows/ci.yml` (lint + build check) but do **not** deploy.

## Manual deploy

To trigger a deploy without a git push:

```
GitHub → Actions → Deploy to GCP → Run workflow
```

## Costs (approximate)

Cloud Run charges only for actual request processing time.
With `min_instances = 0` the idle cost is **~$0/month**.
A typical small team (a few hundred scans/month) stays well within the free tier.

## Updating secrets

Secrets live in GCP Secret Manager. To rotate a value:

```bash
echo -n "new-value" | gcloud secrets versions add horus-llm-api-key --data-file=-
```

Cloud Run picks up the new version on the next cold start (or force a new revision via `gcloud run deploy --image ...`).

## Scaling

Adjust `min_instances` and `max_instances` in `terraform.tfvars` and re-run `terraform apply`.

For high-concurrency scan workloads, also increase `cpu` and `memory`.

## Teardown

```bash
terraform destroy
```

This removes all GCP resources created by Terraform.
The Supabase project and GCS state bucket must be deleted manually.
