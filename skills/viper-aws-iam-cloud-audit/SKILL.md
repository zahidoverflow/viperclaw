---
name: viper-aws-iam-cloud-audit
description: AWS IAM, STS, S3, KMS & Lambda Security Auditor (modeled on Prowler, Parliament & CloudSplaining). Reviews iam:PassRole escalation, STS ExternalId, S3 policies, and IMDSv2.
---

# ViperClaw Skill 48: AWS IAM, STS, S3 & Cloud Posture Auditor (`viper-aws-iam-cloud-audit`)

## 1. Standards & Open-Source Reference
- **Standards:** CIS Amazon Web Services Foundations Benchmark, `prowler-cloud/prowler`, `duo-labs/parliament`, `salesforce/cloudsplaining`.
- **Focus:** Auditing AWS IAM policies, STS trust relationships, S3 bucket policies, KMS key policies, and Lambda configurations.

## 2. Rapid Discovery Patterns
- Search for `"iam:PassRole"`, `"sts:AssumeRole"`, `"Principal": "*"`, `"Action": "*"`, `"NotAction"`, `BlockPublicAcls`, `HttpTokens`.

## 3. Technical Audit Checklist
1. **IAM Privilege Escalation Path Audit:** Flag dangerous permission combinations (`iam:PassRole` + `ec2:RunInstances`/`lambda:CreateFunction`/`glue:CreateDevEndpoint`, `iam:CreatePolicyVersion`, `iam:AttachRolePolicy`, `sts:AssumeRole` with wildcard resources). Scope `iam:PassRole` to specific role ARNs and require `iam:PassedToService` conditions.
2. **Cross-Account STS `ExternalId` & Confused Deputy Defense:** Every cross-account IAM Role trust policy (`AssumeRole`) granted to a third party must enforce a `Condition` checking `sts:ExternalId` (or `aws:SourceArn` / `aws:SourceAccount` for AWS service principals).
3. **S3 Account-Level Public Access Block & Bucket Policies:** Enforce `aws_s3_account_public_access_block` (`block_public_acls = true`, `block_public_policy = true`, `ignore_public_acls = true`, `restrict_public_buckets = true`) and require `aws:SecureTransport = true` on bucket policies.
4. **EC2 / EKS IMDSv2 & Hop-Limit Hardening:** Require `http_tokens = "required"` (IMDSv2) on all EC2 instances and launch templates; on EKS worker nodes, enforce `http_put_response_hop_limit = 1` (or block `169.254.169.254` from pods via NetworkPolicy) and use IRSA / EKS Pod Identity.
5. **Lambda & KMS Least Privilege:** Assign each Lambda function a dedicated execution role (never shared across functions), never store plaintext secrets in Lambda environment variables without KMS envelope encryption, and audit KMS key policies for `Principal: "*"` without strict condition keys.

## 4. Vulnerable vs. Hardened Pattern
```hcl
# ❌ VULNERABLE: Cross-account AssumeRole trust policy without ExternalId & wildcard PassRole
statement {
  effect  = "Allow"
  actions = ["iam:PassRole"]
  resources = ["*"]
}

# ✅ HARDENED: Scoped PassRole to specific role ARN & service condition
statement {
  effect    = "Allow"
  actions   = ["iam:PassRole"]
  resources = [aws_iam_role.worker_task.arn]
  condition {
    test     = "StringEquals"
    variable = "iam:PassedToService"
    values   = ["ecs-tasks.amazonaws.com"]
  }
}
```
