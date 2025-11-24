#!/usr/bin/env bash
set -euo pipefail

# Destroy resources created by provision_gcp.sh. This will attempt to remove resources
# but may fail if there are dependent resources. Use with care.

usage() {
  cat <<EOF
Usage: $0 -p PROJECT [-r REGION] [-c CLUSTER] [-q REPO] [-u POOL_ID] [-v PROVIDER_ID] [-s SA_NAME]

Example:
  $0 -p my-project
EOF
}

PROJECT="prod-le9fxx2ruhbc"
REGION="us-central1"
CLUSTER="vuln-demo-cluster"
REPO="vuln-demo-repo"
POOL_ID="pan-github-pool"
PROVIDER_ID="pan-github-provider"
SA_NAME="github-actions-sa"

while getopts "p:r:c:q:u:v:s:h" opt; do
  case ${opt} in
    p) PROJECT=${OPTARG} ;;
    r) REGION=${OPTARG} ;;
    c) CLUSTER=${OPTARG} ;;
    q) REPO=${OPTARG} ;;
    u) POOL_ID=${OPTARG} ;;
    v) PROVIDER_ID=${OPTARG} ;;
    s) SA_NAME=${OPTARG} ;;
    h) usage; exit 0 ;;
    *) usage; exit 1 ;;
  esac
done

if [[ -z "$PROJECT" ]]; then
  echo "ERROR: -p PROJECT is required" >&2
  usage
  exit 1
fi

echo "Project: $PROJECT"

gcloud config set project "$PROJECT"

echo "Deleting GKE cluster (if exists): $CLUSTER"
if gcloud container clusters describe "$CLUSTER" --region="$REGION" --project="$PROJECT" >/dev/null 2>&1; then
  gcloud container clusters delete "$CLUSTER" --region="$REGION" --project="$PROJECT" --quiet || true
else
  echo "Cluster not found: $CLUSTER"
fi

echo "Deleting Artifact Registry repo: $REPO"
if gcloud artifacts repositories describe "$REPO" --project="$PROJECT" --location="$REGION" >/dev/null 2>&1; then
  gcloud artifacts repositories delete "$REPO" --project="$PROJECT" --location="$REGION" --quiet || true
else
  echo "Artifact repo not found: $REPO"
fi

echo "Deleting subnet and VPC (if exists)"
if gcloud compute networks subnets describe vuln-demo-subnet --region="$REGION" --project="$PROJECT" >/dev/null 2>&1; then
  gcloud compute networks subnets delete vuln-demo-subnet --region="$REGION" --project="$PROJECT" --quiet || true
fi
if gcloud compute networks describe vuln-demo-network --project="$PROJECT" >/dev/null 2>&1; then
  gcloud compute networks delete vuln-demo-network --project="$PROJECT" --quiet || true
fi

SA_EMAIL="$SA_NAME@$PROJECT.iam.gserviceaccount.com"
echo "Removing IAM bindings and service account: $SA_EMAIL"
gcloud projects remove-iam-policy-binding "$PROJECT" --member="serviceAccount:$SA_EMAIL" --role="roles/artifactregistry.writer" --quiet || true
gcloud projects remove-iam-policy-binding "$PROJECT" --member="serviceAccount:$SA_EMAIL" --role="roles/container.developer" --quiet || true
gcloud projects remove-iam-policy-binding "$PROJECT" --member="serviceAccount:$SA_EMAIL" --role="roles/iam.serviceAccountUser" --quiet || true
if gcloud iam service-accounts describe "$SA_EMAIL" --project="$PROJECT" >/dev/null 2>&1; then
  gcloud iam service-accounts delete "$SA_EMAIL" --project="$PROJECT" --quiet || true
fi

echo "Deleting Workload Identity provider and pool (if exists)"
if gcloud iam workload-identity-pools providers describe "$PROVIDER_ID" --project="$PROJECT" --location=global --workload-identity-pool="$POOL_ID" >/dev/null 2>&1; then
  gcloud iam workload-identity-pools providers delete "$PROVIDER_ID" --project="$PROJECT" --location=global --workload-identity-pool="$POOL_ID" --quiet || true
fi
if gcloud iam workload-identity-pools describe "$POOL_ID" --project="$PROJECT" --location=global >/dev/null 2>&1; then
  gcloud iam workload-identity-pools delete "$POOL_ID" --project="$PROJECT" --location=global --quiet || true
fi

echo "Destroy complete (best-effort)."

exit 0
