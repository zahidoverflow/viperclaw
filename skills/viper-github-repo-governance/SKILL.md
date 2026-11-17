---
name: viper-github-repo-governance
description: GitHub Organization, Branch Protection & OpenSSF Scorecard Auditor. Reviews branch protection rules, signed commits, CODEOWNERS, secret scanning, and GitHub App scopes.
---

# ViperClaw Skill 58: GitHub Repository Governance & OpenSSF Scorecard Auditor (`viper-github-repo-governance`)

## 1. Standards & Open-Source Reference
- **Standards:** `ossf/scorecard` (OpenSSF Security Scorecard), SLSA Source Requirements, CIS GitHub Benchmark.
- **Focus:** Auditing GitHub repository settings, branch rulesets, `CODEOWNERS`, `SECURITY.md`, and Dependabot/CodeQL configurations.

## 2. Rapid Discovery Patterns
- Inspect `.github/CODEOWNERS`, `.github/dependabot.yml`, `.github/workflows/codeql.yml`, `SECURITY.md`, and branch protection rulesets.

## 3. Technical Audit Checklist
1. **Branch Rulesets & PR Review Enforcement:** Protect `main`/`master` and release branches with mandatory pull-request reviews (`required_approving_review_count >= 1`), `dismiss_stale_reviews_on_push = true`, `require_code_owner_review = true`, required status checks, and block force-pushes and branch deletions.
2. **Protected `.github/CODEOWNERS` Coverage:** Ensure `.github/CODEOWNERS` assigns security-team ownership to `.github/workflows/`, `Dockerfile*`, `terraform/`, authentication modules, and `CODEOWNERS` itself.
3. **Automated Dependabot, Secret Scanning & Push Protection:** Enable GitHub Secret Scanning with **Push Protection**, Dependabot security updates (`.github/dependabot.yml` covering both package ecosystems and `github-actions`), and CodeQL / ViperClaw SARIF code scanning.
4. **Commit Signing & Tag Protection:** Require cryptographic commit signing (GPG / SSH / Sigstore `gitsign`) on default branches and protect release tag patterns (`v*`) from modification or deletion by non-maintainers.
5. **GitHub Actions Organization Settings:** Configure default workflow permissions at the repository/org level to **Read repository contents and packages permissions** (`default_workflow_permissions: read`) and disable `can_approve_pull_request_reviews`.

## 4. Vulnerable vs. Hardened Pattern
```yaml
# ✅ HARDENED: .github/dependabot.yml covering both application dependencies & github-actions
version: 2
updates:
  - package-ecosystem: "pip"
    directory: "/"
    schedule:
      interval: "weekly"
  - package-ecosystem: "github-actions"
    directory: "/"
    schedule:
      interval: "weekly"
```
