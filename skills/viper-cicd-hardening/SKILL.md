---
name: viper-cicd-hardening
description: CI/CD Pipeline & GitHub Actions Security Auditor (modeled on Zizmor, Actionlint & StepSecurity). Reviews workflow permissions, untrusted PR triggers, script interpolation, and SHA pinning.
---

# ViperClaw Skill 17: CI/CD Pipeline & GitHub Actions Auditor (`viper-cicd-hardening`)

## Overview
Audits `.github/workflows/*.yml`, `.gitlab-ci.yml`, and Jenkinsfiles for workflow expression injection, excessive `GITHUB_TOKEN` permissions, and insecure artifact handling.

## Audit Checklist
1. **Untrusted Expression Interpolation:** Never interpolate `${{ github.event.issue.title }}`, `pull_request.title`, `head_ref`, or commit messages directly inside `run:` shell blocks—pass them via `env:` variables instead.
2. **`pull_request_target` & Fork Safety:** Avoid checking out untrusted fork PR code (`refs/pull/*/merge`) inside privileged `pull_request_target` workflows that have write access or secrets.
3. **Least-Privilege `permissions` & SHA Pinning:** Declare top-level `permissions: contents: read` by default and pin third-party GitHub Actions to full 40-character commit SHAs.
