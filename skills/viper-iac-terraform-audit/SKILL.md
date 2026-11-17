---
name: viper-iac-terraform-audit
description: Infrastructure-as-Code (Terraform, CloudFormation & Pulumi) Security Auditor (modeled on Checkov & tfsec). Reviews IAM least privilege, storage encryption, public buckets, and security groups.
---

# ViperClaw Skill 19: Infrastructure-as-Code (Terraform / Cloud) Auditor (`viper-iac-terraform-audit`)

## Overview
Audits Terraform (`*.tf`), AWS CloudFormation, and Pulumi definitions for overly permissive IAM policies, publicly exposed storage buckets, unencrypted data stores, and wide-open ingress rules.

## Audit Checklist
1. **IAM Least Privilege:** Flag `Action: "*"` or `Resource: "*"` in IAM policies, overly broad STS assume-role trust policies, and unused long-lived IAM user access keys.
2. **Storage & Database Isolation:** Ensure S3/GCS/Azure Blob buckets enforce public-access blocks, server-side encryption (KMS), and access logging; confirm RDS/Redis instances are in private subnets.
3. **Network Ingress Controls:** Reject security group rules allowing `0.0.0.0/0` or `::/0` ingress on administrative or database ports (`22`, `3389`, `5432`, `3306`, `6379`, `27017`).
