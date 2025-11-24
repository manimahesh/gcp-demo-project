# GCloud provisioning scripts

This folder contains bash scripts to provision and destroy GCP resources for the vuln-demo project using `gcloud`.

Files:

- `provision_gcp.sh` — idempotent provisioning script. Creates Artifact Registry, VPC/subnet, GKE cluster, service account, IAM bindings, and Workload Identity Pool + Provider. Prints the values you should add as GitHub secrets.
- `destroy_gcp.sh` — best-effort destroy script to remove the created resources.

Additional flags:

- `--recreate-provider` or `-R`: if the OIDC provider already exists, delete and recreate it with the repository-scoped attribute mapping and attribute condition. Useful when you change `OWNER_REPO` or update the provider mapping.

Notes:

- These scripts are intended for demos and development. Review before running in production.
- Run these in Cloud Shell or a Linux shell where `gcloud` SDK is installed and authenticated.
- The scripts bind the Workload Identity Pool to the service account using a `principalSet` wildcard by default to enable GitHub Actions quickly. You can refine the bindings later with attribute-based IAM conditions.

Example usage:

```bash
# Provision
bash provision_gcp.sh -p my-project -r us-central1 -o myorg/myrepo

# Destroy
bash destroy_gcp.sh -p my-project
```
