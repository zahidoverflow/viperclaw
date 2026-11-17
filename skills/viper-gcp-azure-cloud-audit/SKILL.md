---
name: viper-gcp-azure-cloud-audit
description: Google Cloud (GCP) & Microsoft Azure Security Posture Auditor (modeled on ScoutSuite & Prowler). Reviews Workload Identity, Service Accounts, Managed Identities, and NSGs.
---

# ViperClaw Skill 49: GCP & Microsoft Azure Security Posture Auditor (`viper-gcp-azure-cloud-audit`)

## 1. Standards & Open-Source Reference
- **Standards:** CIS Google Cloud Platform & Microsoft Azure Foundations Benchmarks, NCC Group `ScoutSuite`, Prowler GCP/Azure.
- **Focus:** Auditing GCP IAM/GKE/Cloud Storage and Azure Entra ID/Managed Identities/Key Vault/NSGs.

## 2. Rapid Discovery Patterns
- **GCP:** `allUsers`, `allAuthenticatedUsers`, `iam.serviceAccountTokenCreator`, `iam.serviceAccountUser`, `google_service_account_key`.
- **Azure:** `allow_blob_public_access`, `enable_rbac_authorization`, `source_address_prefix = "*"`, `UserAssigned`, `SystemAssigned`.

## 3. Technical Audit Checklist
1. **Eliminate Long-Lived Service Account Keys (Workload Identity Federation):** Flag `google_service_account_key` and Azure Service Principal client secrets; migrate CI/CD and multi-cloud workloads to **Workload Identity Federation (OIDC)** and **GKE Workload Identity / Azure Managed Identities**.
2. **GCP Default Compute Service Account & OAuth Scopes:** Never run GCE instances or GKE node pools under the default `PROJECT_NUMBER-compute@developer.gserviceaccount.com` account with `cloud-platform` full access scope; create dedicated least-privilege service accounts.
3. **Public IAM Bindings (`allUsers` / `allAuthenticatedUsers` / Anonymous Blob):** Audit Cloud Storage, BigQuery datasets, Cloud Run services, and Azure Storage Accounts to ensure `allUsers`, `allAuthenticatedUsers`, and `allow_nested_items_to_be_public` are disabled unless explicitly intended for public static assets.
4. **IAM Impersonation & Privilege Escalation Roles:** Audit bindings for `roles/iam.serviceAccountTokenCreator`, `roles/iam.serviceAccountKeyAdmin`, `roles/deploymentmanager.editor`, and Azure `Owner` / `User Access Administrator` at the subscription/project root.
5. **VPC Firewall & Azure NSG Segmentation:** Reject GCP firewall rules and Azure Network Security Groups allowing `0.0.0.0/0` ingress to management ports (`22`, `3389`, `6443`) or internal VPC subnets; enforce Cloud IAP / Azure Bastion and Private Service Connect / Private Endpoints.

## 4. Vulnerable vs. Hardened Pattern
```hcl
# ❌ VULNERABLE: Exports static GCP service account JSON key & binds Editor role
resource "google_service_account_key" "ci_key" {
  service_account_id = google_service_account.ci.name
}
resource "google_project_iam_member" "ci_editor" {
  project = var.project_id
  role    = "roles/editor"
  member  = "serviceAccount:${google_service_account.ci.email}"
}

# ✅ HARDENED: Keyless Workload Identity Pool + granular artifact registry role
resource "google_project_iam_member" "ci_Artifact_writer" {
  project = var.project_id
  role    = "roles/artifactregistry.writer"
  member  = "principalSet://iam.googleapis.com/${google_iam_workload_identity_pool.gh.name}/attribute.repository/${var.github_repo}"
}
```
