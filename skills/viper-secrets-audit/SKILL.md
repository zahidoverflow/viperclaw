---
name: viper-secrets-audit
description: Hardcoded Secret, Credential Entropy & Git History Leak Auditor (modeled on Gitleaks & TruffleHog). Scans codebases, configs, and CI files for exposed API keys and private tokens.
---

# ViperClaw Skill 15: Hardcoded Secret & Credential Leak Auditor (`viper-secrets-audit`)

## Overview
Audits source repositories, configuration files, client bundles, and git history for hardcoded secrets, high-entropy tokens, and private keys (CWE-798), inspired by Gitleaks and TruffleHog rulesets.

## Audit Checklist
1. **High-Risk Secret Patterns:** Check for AWS (`AKIA...`), GCP service-account JSONs, GitHub PATs (`ghp_`, `github_pat_`), Stripe keys (`sk_live_`), Slack tokens (`xoxb-`), private PEM keys, and database connection URLs with embedded passwords.
2. **Environment & Ignore Hygiene:** Verify `.env`, `.npmrc`, `kubeconfig`, and `*.pem` are listed in `.gitignore` and `.dockerignore`, and provide `.env.example` templates with placeholder values only.
3. **Remediation:** Revoke/rotate any exposed credential immediately and migrate secret storage to a dedicated secret manager (Vault, AWS Secrets Manager, GitHub Encrypted Secrets).
