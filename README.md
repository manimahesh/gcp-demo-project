# GCP Vulnerable Web App Demo

This repository is a small, intentionally vulnerable web application used for training: a static frontend (demo slides) and a Node.js backend that exposes endpoints illustrating common security issues.

WARNING: This project is intentionally vulnerable. Run only in an isolated test project or local environment and never expose it to production or the public internet.

**Quick Start — Local**

- Prereqs: Node.js 18+, npm, and Docker (optional).
- Start locally from the repo root:

```pwsh
cd app
npm ci
npm start
```

- Open `http://localhost:8080` to view the demo UI.

**What changed**

- The backend no longer requires `sqlite3` (native addon). It uses an in-memory `users` array for the SQLi/IDOR demos, so you can run the app without compiling native modules.

**Run in Docker (local)**

```pwsh
# build (from repo root so frontend is included)
docker build -f app/Dockerfile -t vuln-backend:local .
# run
docker run --rm -p 8080:8080 vuln-backend:local
```

Then visit `http://localhost:8080`.

**Deploy to GCP (helper scripts)**

This repo includes idempotent gcloud helper scripts to provision resources instead of Terraform. See `scripts/gcloud/provision_gcp.sh` and `scripts/gcloud/destroy_gcp.sh`.

Typical flow (interactive):

```pwsh
# provision resources (APIs, AR repo, VPC, GKE, service accounts, Workload Identity)
cd scripts/gcloud
pwsh ./provision_gcp.sh --project YOUR_PROJECT_ID --region us-central1

# after provisioning, either run CI or push image manually
# authenticate gcloud then build & push
gcloud auth configure-docker us-central1-docker.pkg.dev
docker build -f app/Dockerfile -t us-central1-docker.pkg.dev/YOUR_PROJECT_ID/vuln-demo-repo/backend:latest .
docker push us-central1-docker.pkg.dev/YOUR_PROJECT_ID/vuln-demo-repo/backend:latest
```

The provisioning script prints required values (service account email, Workload Identity provider name) to add to GitHub repository secrets (`GCP_PROJECT`, `GCP_WIF_PROVIDER`, `GCP_SA_EMAIL`, `GKE_CLUSTER_NAME`).

**CI / GitHub Actions**

- The workflow `.github/workflows/ci-build-and-push.yml` builds the Docker image and deploys the `k8s/backend-deployment.yaml` manifest. It expects the image tag format: `us-central1-docker.pkg.dev/$PROJECT/vuln-demo-repo/backend:latest`.
- The repo uses OIDC/Workload Identity for GitHub Actions — see `scripts/gcloud/provision_gcp.sh` for how the provider and bindings are created.

**Endpoints overview (selected)**

- `GET /api/sqli?name=alice` — simulated SQLi demo (in-memory). Supplying values that look like SQL injection (quotes or `OR`) will return all users to demonstrate the risk.
- `POST /api/xss` and `GET /api/xss/comments` — XSS demo (no output encoding in frontend).
- `POST /api/auth/login` and `GET /api/auth/me` — broken JWT auth demo (weak secret).
- `GET /api/idor/user/:id` — IDOR demo (no authorization checks).
- `GET /healthz` — health probe.

**Security / Safety**

- Do not run this in production. Use a disposable GCP project. All scripts and manifests aim to be minimal and educational.
- Resources created by `provision_gcp.sh` include labels with `Owner=\"PAN\"` where supported.

**Troubleshooting**

- If you previously had sqlite3 problems, those were due to native addon binaries; the current code removes `sqlite3` so you should not see those errors.
- For container image push/pull issues, ensure the node (GKE) service account has `roles/artifactregistry.reader` and that GitHub Actions secrets are configured.

If you'd like, I can:

- Add persistence (JSON file or a lightweight JS DB) so data survives container restarts.
- Reintroduce sqlite3 but add multi-arch Buildx builds that compile native modules per-architecture.

---

See `scripts/gcloud/README.md` for details about the GCP provisioning scripts.
