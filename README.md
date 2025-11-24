# GCP Vulnerable Web App Demo

This repository contains a small demo web application designed to teach developers about 10 common web application vulnerabilities. It includes a static frontend (carousel of demos), a Node.js backend exposing intentionally vulnerable endpoints (for demonstration only), Dockerfiles, a Terraform skeleton for provisioning GCP resources, and GitHub Actions workflow templates.

WARNING: This project is intentionally vulnerable for training purposes. Run only in a dedicated test GCP project and never expose it publicly.

Quick start (local):

1. Install Node.js 18+ and Docker (optional for container runs).
2. From the `backend` folder, install dependencies and start the server:

```pwsh
cd backend
npm install
node server.js
```

3. Open `http://localhost:8080` in your browser. The frontend is served by the backend.

Automated local tests

1. Start the backend:

```pwsh
cd backend
npm install
node server.js
```

2. In another PowerShell session run the supplied test script to exercise endpoints and save results:

```pwsh
cd ..\scripts
pwsh .\test-endpoints.ps1
```

Test outputs will be saved to `scripts/test-results/`.

Build Docker image (optional):

```pwsh
cd backend
docker build -t vuln-demo-backend:latest .
```

Terraform:

- The `terraform/` folder contains a skeleton to enable APIs, create Artifact Registry, a VPC/subnet, service accounts, IAM bindings, and a basic GKE cluster. All resources that support labels include `Owner = "PAN"`.
- Before applying, set the variables in `terraform/variables.tf` or pass them on the command line (e.g. `-var="project_id=your-project"`). Authenticate using `gcloud auth application-default login` or configure Workload Identity for GitHub Actions.

Basic terraform commands:

```pwsh
cd terraform
terraform init
terraform plan -var="project_id=YOUR_PROJECT_ID" -var="region=us-central1"
# when ready:
terraform apply -var="project_id=YOUR_PROJECT_ID" -var="region=us-central1"
```

CI/CD:

- `.github/workflows/ci-build-and-push.yml` builds images and pushes to Artifact Registry (OIDC-based auth recommended).
- `.github/workflows/ci-terraform.yml` contains a skeleton for plan/apply with OIDC.

Next steps:

- Review `terraform/` and add your project-specific values.
- Run the app locally and explore the slides.
- Ask me to run tests or to add more realistic GKE manifests.
