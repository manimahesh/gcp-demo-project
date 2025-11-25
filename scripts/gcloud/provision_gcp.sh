#!/usr/bin/env bash
set -euo pipefail

# Provision GCP resources using gcloud commands (idempotent where practical).
# This script is intended for demos and small test projects. Review before running in production.

usage() {
  cat <<EOF
Usage: $0 -p PROJECT [-r REGION] [-c CLUSTER] [-o OWNER_REPO]

Environment/Args:
  -p PROJECT      GCP project ID (required)
  -r REGION       Region (default: us-central1)
  -c CLUSTER      GKE cluster name (default: vuln-demo-cluster)
  -q REPO         Artifact Registry repo id (default: vuln-demo-repo)
  -u POOL_ID      Workload Identity Pool id (default: pan-github-pool)
  -v PROVIDER_ID  Workload Identity Provider id (default: pan-github-provider)
  -s SA_NAME      Service account name (default: github-actions-sa)
  -o OWNER_REPO   GitHub owner/repo (default: example-org/example-repo)

Example:
  $0 -p my-project -r us-central1 -o myorg/myrepo
EOF
}

PROJECT="prod-le9fxx2ruhbc"
REGION="us-central1"
CLUSTER="vuln-demo-cluster"
REPO="vuln-demo-repo"
RECREATE_PROVIDER=false

# allow long flag --recreate-provider in addition to short -R
for a in "$@"; do
  if [[ "$a" == "--recreate-provider" ]]; then
    RECREATE_PROVIDER=true
    # remove the long flag so getopts doesn't choke on it
    set -- "${@//--recreate-provider/}"
    break
  fi
done
POOL_ID="github-actions-pool"
PROVIDER_ID="github-provider"
SA_NAME="github-actions-sa"
OWNER_REPO="manimahesh/gcp-demo-project"

while getopts "p:r:c:q:u:v:s:o:h" opt; do
  case ${opt} in
    p) PROJECT=${OPTARG} ;;
    r) REGION=${OPTARG} ;;
    c) CLUSTER=${OPTARG} ;;
    q) REPO=${OPTARG} ;;
    u) POOL_ID=${OPTARG} ;;
    v) PROVIDER_ID=${OPTARG} ;;
    s) SA_NAME=${OPTARG} ;;
    o) OWNER_REPO=${OPTARG} ;;
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
echo "Region: $REGION"
echo "Cluster: $CLUSTER"
echo "Artifact Repo: $REPO"
echo "WIF Pool: $POOL_ID, Provider: $PROVIDER_ID"
echo "Service Account: $SA_NAME"
echo "GitHub Owner/Repo: $OWNER_REPO"

gcloud config set project "$PROJECT"

echo "Enabling required APIs..."
gcloud services enable --project="$PROJECT" \
  container.googleapis.com artifactregistry.googleapis.com cloudbuild.googleapis.com iam.googleapis.com compute.googleapis.com storage.googleapis.com || true

echo "Creating Artifact Registry repo (if not exists): $REPO"
if ! gcloud artifacts repositories describe "$REPO" --project="$PROJECT" --location="$REGION" >/dev/null 2>&1; then
  gcloud artifacts repositories create "$REPO" --project="$PROJECT" --location="$REGION" --repository-format=docker --description="Container images for vuln demo" --labels=owner=pan,purpose=vuln-demo
else
  echo "Artifact repo $REPO already exists"
fi

echo "Creating VPC and subnet (idempotent)"
if ! gcloud compute networks describe vuln-demo-network --project="$PROJECT" >/dev/null 2>&1; then
  gcloud compute networks create vuln-demo-network --project="$PROJECT" --subnet-mode=custom --description="Vuln demo VPC"
else
  echo "VPC vuln-demo-network exists"
fi

if ! gcloud compute networks subnets describe vuln-demo-subnet --region="$REGION" --project="$PROJECT" >/dev/null 2>&1; then
  gcloud compute networks subnets create vuln-demo-subnet --project="$PROJECT" --region="$REGION" --network=vuln-demo-network --range=10.10.0.0/24
else
  echo "Subnet vuln-demo-subnet exists"
fi

echo "Creating GKE cluster (idempotent)"
if ! gcloud container clusters describe "$CLUSTER" --region="$REGION" --project="$PROJECT" >/dev/null 2>&1; then
  # Create a VPC-native cluster attached to our custom VPC/subnet so gcloud
  # doesn't attempt to use the (possibly removed) default network.
  gcloud container clusters create "$CLUSTER" \
    --region="$REGION" \
    --num-nodes=1 \
    --no-enable-basic-auth \
    --enable-ip-alias \
    --network="vuln-demo-network" \
    --subnetwork="vuln-demo-subnet" \
    --labels=owner=pan,purpose=vuln-demo \
    --project="$PROJECT" \
    --node-locations="$REGION-a"
else
  echo "GKE cluster $CLUSTER already exists"
fi

# Ensure the cluster node service account can pull images from Artifact Registry
echo "Determining GKE node service account for cluster $CLUSTER"
NODE_SA=$(gcloud container clusters describe "$CLUSTER" --region="$REGION" --project="$PROJECT" --format='value(nodeConfig.serviceAccount)') || true
if [ -z "$NODE_SA" ]; then
  echo "Cluster node service account not explicitly set; constructing default compute service account"
  PROJECT_NUMBER=$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')
  NODE_SA="$PROJECT_NUMBER-compute@developer.gserviceaccount.com"
fi
echo "Granting roles/artifactregistry.reader to node service account: $NODE_SA"
gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:$NODE_SA" --role="roles/artifactregistry.reader" --quiet || true

# Also grant storage.objectViewer to GKE nodes so pods can access storage buckets
echo "Granting roles/storage.objectViewer to node service account: $NODE_SA"
gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:$NODE_SA" --role="roles/storage.objectViewer" --quiet || true

# Create Cloud Storage Buckets for the demo
BUCKET_VULNERABLE="$PROJECT-vuln-demo-public-pii"
BUCKET_SECURE="$PROJECT-vuln-demo-secure-pii"

echo "Creating VULNERABLE (public) storage bucket: $BUCKET_VULNERABLE"
if ! gsutil ls -b "gs://$BUCKET_VULNERABLE" >/dev/null 2>&1; then
  gsutil mb -p "$PROJECT" -l "$REGION" "gs://$BUCKET_VULNERABLE"
  # Make bucket publicly readable (INTENTIONALLY INSECURE for demo)
  gsutil iam ch allUsers:objectViewer "gs://$BUCKET_VULNERABLE"
  echo "⚠️  WARNING: Bucket $BUCKET_VULNERABLE is now PUBLIC for demo purposes!"
else
  echo "Vulnerable bucket already exists"
fi

echo "Creating SECURE (private) storage bucket: $BUCKET_SECURE"
if ! gsutil ls -b "gs://$BUCKET_SECURE" >/dev/null 2>&1; then
  gsutil mb -p "$PROJECT" -l "$REGION" "gs://$BUCKET_SECURE"
  # Enable uniform bucket-level access (best practice)
  gsutil uniformbucketlevelaccess set on "gs://$BUCKET_SECURE"
  # Enable versioning
  gsutil versioning set on "gs://$BUCKET_SECURE"
  echo "✅ Secure bucket created with uniform access and versioning"
else
  echo "Secure bucket already exists"
fi

# Upload the PII CSV to both buckets
echo "Uploading customer PII data to buckets..."
if [ -f "app/data/customer_pii.csv" ]; then
  gsutil cp app/data/customer_pii.csv "gs://$BUCKET_VULNERABLE/customer_pii.csv"
  gsutil cp app/data/customer_pii.csv "gs://$BUCKET_SECURE/customer_pii.csv"
  echo "CSV files uploaded to both buckets"
else
  echo "⚠️  Warning: app/data/customer_pii.csv not found, skipping upload"
fi

echo "Creating service account: $SA_NAME"
SA_EMAIL="$SA_NAME@$PROJECT.iam.gserviceaccount.com"
if ! gcloud iam service-accounts describe "$SA_EMAIL" --project="$PROJECT" >/dev/null 2>&1; then
  gcloud iam service-accounts create "$SA_NAME" --project="$PROJECT" --display-name="GitHub Actions service account"
else
  echo "Service account $SA_EMAIL exists"
fi

echo "Granting roles to service account"
gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:$SA_EMAIL" --role="roles/artifactregistry.writer" --quiet || true
gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:$SA_EMAIL" --role="roles/container.developer" --quiet || true
gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:$SA_EMAIL" --role="roles/iam.serviceAccountUser" --quiet || true
gcloud projects add-iam-policy-binding "$PROJECT" --member="serviceAccount:$SA_EMAIL" --role="roles/storage.admin" --quiet || true

PROJECT_NUMBER=$(gcloud projects describe "$PROJECT" --format='value(projectNumber)')

echo "Creating Workload Identity Pool (if not exists): $POOL_ID"
if ! gcloud iam workload-identity-pools describe "$POOL_ID" --project="$PROJECT" --location=global >/dev/null 2>&1; then
  gcloud iam workload-identity-pools create "$POOL_ID" --project="$PROJECT" --location="global" --display-name="GitHub Actions Pool"
else
  echo "WIF pool $POOL_ID exists"
fi

echo "Active gcloud account: $(gcloud auth list --filter=status:ACTIVE --format='value(account)')"
echo "gcloud project: $(gcloud config get-value project 2>/dev/null || echo '<none>')"

# Wait for the pool to be visible/propagated before creating the provider
echo "Waiting for Workload Identity Pool to be ready..."
RETRY=0
MAX_RETRIES=12
SLEEP_SECONDS=5
until gcloud iam workload-identity-pools describe "$POOL_ID" --project="$PROJECT" --location=global >/dev/null 2>&1; do
  ((RETRY++))
  if [ $RETRY -gt $MAX_RETRIES ]; then
    echo "Timed out waiting for pool '$POOL_ID' to become available. Run the following to debug:"
    echo "  gcloud auth list"
    echo "  gcloud config get-value project"
    echo "  gcloud iam workload-identity-pools list --project=$PROJECT --location=global"
    echo "  gcloud iam workload-identity-pools describe $POOL_ID --project=$PROJECT --location=global --format=json"
    exit 1
  fi
  echo "  pool not ready yet (attempt $RETRY/$MAX_RETRIES), sleeping $SLEEP_SECONDS seconds..."
  sleep $SLEEP_SECONDS
done

echo "Creating OIDC provider (if not exists): $PROVIDER_ID"
if ! gcloud iam workload-identity-pools providers describe "$PROVIDER_ID" --project="$PROJECT" --location=global --workload-identity-pool="$POOL_ID" >/dev/null 2>&1; then
  # Create OIDC provider. Map the repository claim and add an attribute condition
  # so only tokens issued for the configured repository are accepted.
  gcloud iam workload-identity-pools providers create-oidc "$PROVIDER_ID" \
    --project="$PROJECT" --location="global" --workload-identity-pool="$POOL_ID" \
    --display-name="GitHub Actions OIDC provider" \
    --issuer-uri="https://token.actions.githubusercontent.com" \
    --allowed-audiences="https://github.com/$OWNER_REPO" \
    --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository" \
    --attribute-condition="attribute.repository=='$OWNER_REPO'"
else
  echo "Provider $PROVIDER_ID already exists in pool $POOL_ID"
fi
PROVIDER_EXISTS=false
if gcloud iam workload-identity-pools providers describe "$PROVIDER_ID" --project="$PROJECT" --location=global --workload-identity-pool="$POOL_ID" >/dev/null 2>&1; then
  PROVIDER_EXISTS=true
fi

if $PROVIDER_EXISTS; then
  if $RECREATE_PROVIDER; then
    echo "Recreating existing provider: $PROVIDER_ID"
    gcloud iam workload-identity-pools providers delete "$PROVIDER_ID" --project="$PROJECT" --location=global --workload-identity-pool="$POOL_ID" --quiet || true
    sleep 1
    echo "Creating provider $PROVIDER_ID in pool $POOL_ID"
    gcloud iam workload-identity-pools providers create-oidc "$PROVIDER_ID" \
      --project="$PROJECT" \
      --location="global" \
      --workload-identity-pool="$POOL_ID" \
      --display-name="GitHub Actions OIDC provider" \
      --issuer-uri="https://token.actions.githubusercontent.com" \
      --allowed-audiences="https://github.com/$OWNER_REPO" \
      --attribute-mapping="google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.repository=assertion.repository,attribute.repository_owner=assertion.repository_owner" \
      --attribute-condition="attribute.repository=='$OWNER_REPO'"
  else
    echo "Provider $PROVIDER_ID already exists in pool $POOL_ID. Use --recreate-provider to replace it with updated mappings/conditions."
  fi
else
  echo "Creating provider $PROVIDER_ID in pool $POOL_ID"
  gcloud iam workload-identity-pools providers create-oidc "$PROVIDER_ID" \
    --project="$PROJECT" --location="global" --workload-identity-pool="$POOL_ID" \
    --display-name="GitHub Actions OIDC provider" \
    --issuer-uri="https://token.actions.githubusercontent.com" \
    --allowed-audiences="https://github.com/$OWNER_REPO" \
    --attribute-mapping="google.subject=assertion.sub,attribute.actor=assertion.actor,attribute.repository=assertion.repository,attribute.repository_owner=assertion.repository_owner" \
    --attribute-condition="attribute.repository=='$OWNER_REPO'"
fi

echo "Binding Workload Identity Pool to service account (principalSet wildcard)"
gcloud iam service-accounts add-iam-policy-binding "$SA_EMAIL" --project="$PROJECT" --role="roles/iam.workloadIdentityUser" --member="principalSet://iam.googleapis.com/projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_ID/*" || true

echo "Provisioning complete. Set these values as GitHub Secrets in your repository:"
echo "  GCP_WIF_PROVIDER=projects/$PROJECT_NUMBER/locations/global/workloadIdentityPools/$POOL_ID/providers/$PROVIDER_ID"
echo "  GCP_SA_EMAIL=$SA_EMAIL"
echo "  GCP_PROJECT=$PROJECT"
echo "  GKE_CLUSTER_NAME=$CLUSTER"
echo ""
echo "Storage buckets created:"
echo "  VULNERABLE (PUBLIC): gs://$BUCKET_VULNERABLE"
echo "  SECURE (PRIVATE):    gs://$BUCKET_SECURE"
echo ""
echo "⚠️  WARNING: The vulnerable bucket is intentionally PUBLIC for demo purposes!"
echo "   View public URL: https://storage.googleapis.com/$BUCKET_VULNERABLE/customer_pii.csv"
echo ""
echo "Note: This script uses a principalSet wildcard binding by default to quickly enable GitHub Actions."
echo "Refine the IAM binding later with attribute-based conditions after adjusting provider attribute mapping if desired."

exit 0
