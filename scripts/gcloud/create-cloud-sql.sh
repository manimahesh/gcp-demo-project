# Create Cloud SQL PostgreSQL instance
CLOUD_SQL_INSTANCE="vuln-demo-db"
DB_VERSION="POSTGRES_17"
DB_TIER="db-f1-micro"  # Smallest tier for demo
DB_NAME="vulndb"
DB_USER="vulnuser"
PROJECT="prod-le9fxx2ruhbc"
REGION="us-central1"  
# Generate a random password (in production, use Secret Manager)
DB_PASSWORD=$(openssl rand -base64 32 | tr -d "=+/" | cut -c1-25)

echo "Creating Cloud SQL PostgreSQL instance: $CLOUD_SQL_INSTANCE"
if ! gcloud sql instances describe "$CLOUD_SQL_INSTANCE" --project="$PROJECT" >/dev/null 2>&1; then
  gcloud sql instances create "$CLOUD_SQL_INSTANCE" \
    --database-version="$DB_VERSION" \
    --tier="$DB_TIER" \
    --region="$REGION" \
    --network="projects/$PROJECT/global/networks/vuln-demo-network" \
    --no-assign-ip \
    --project="$PROJECT"

  echo "Waiting for Cloud SQL instance to be ready..."
  gcloud sql operations wait --project="$PROJECT" \
    $(gcloud sql operations list --instance="$CLOUD_SQL_INSTANCE" --project="$PROJECT" --limit=1 --format="value(name)") || true

  echo "✅ Cloud SQL instance created"
else
  echo "Cloud SQL instance $CLOUD_SQL_INSTANCE already exists"
fi

# Set root password
echo "Setting postgres user password..."
gcloud sql users set-password postgres \
  --instance="$CLOUD_SQL_INSTANCE" \
  --password="$DB_PASSWORD" \
  --project="$PROJECT" || true

# Create application database
echo "Creating database: $DB_NAME"
if ! gcloud sql databases describe "$DB_NAME" --instance="$CLOUD_SQL_INSTANCE" --project="$PROJECT" >/dev/null 2>&1; then
  gcloud sql databases create "$DB_NAME" --instance="$CLOUD_SQL_INSTANCE" --project="$PROJECT"
  echo "Database $DB_NAME created"
else
  echo "Database $DB_NAME already exists"
fi

# Create application user
echo "Creating database user: $DB_USER"
if ! gcloud sql users list --instance="$CLOUD_SQL_INSTANCE" --project="$PROJECT" | grep -q "^$DB_USER"; then
  gcloud sql users create "$DB_USER" \
    --instance="$CLOUD_SQL_INSTANCE" \
    --password="$DB_PASSWORD" \
    --project="$PROJECT"
  echo "Database user $DB_USER created"
else
  echo "Database user $DB_USER already exists"
fi

# Get Cloud SQL connection name
CLOUD_SQL_CONNECTION_NAME=$(gcloud sql instances describe "$CLOUD_SQL_INSTANCE" --project="$PROJECT" --format='value(connectionName)')
CLOUD_SQL_PRIVATE_IP=$(gcloud sql instances describe "$CLOUD_SQL_INSTANCE" --project="$PROJECT" --format='value(ipAddresses[0].ipAddress)')
