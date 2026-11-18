---
name: viperclaw
description: Master ViperClaw Security Audit & Remediation entrypoint (`/viperclaw`). Guides authorized source-code SAST, bundle manifest review, configuration/header inspection, and evidence-backed SARIF reporting across all 64 specialized ViperClaw security audit skills.
---

# ViperClaw Master Security Audit & Remediation Entrypoint (`/viperclaw`)

Use this skill whenever the user invokes `/viperclaw` or requests a comprehensive security code review, configuration/posture audit, or OWASP/CWE remediation workflow.

## 5-Phase Security Audit Workflow

1. **Phase 1 — Surface, Bundle & Trust-Boundary Inventory (`viper-orchestrator`, `viper-threat-model-stride`):**
   - For repositories: run `viper_taint_scan` (`viperclaw taint . --db .viperclaw/graph.db`) and `viper_harvest_js` (`viperclaw harvest-js . --db .viperclaw/graph.db`).
   - For HTTP endpoints or HAR captures: run `viper_fingerprint_traffic` (`viperclaw fingerprint`) or `viper_live_scan` for non-destructive CORS, security-header, and public schema posture inspection.
2. **Phase 2 — Stack & Domain Audit Routing (64 Specialized Audit Skills):**
   - **Web / API Authorization & Input:** `viper-bola-idor`, `viper-injection-oracle`, `viper-ssrf-cloud`, `viper-auth-oauth-jwt`, `viper-graphql-ws`, `viper-race-logic`, `viper-openapi-rest-schema`.
   - **Language & Framework Stacks:** `viper-nextjs-react-rsc`, `viper-fastapi-django-flask`, `viper-nodejs-express-nestjs`, `viper-go-service-audit`, `viper-rust-memory-unsafe`, `viper-java-spring-audit`, `viper-php-laravel-wordpress`, `viper-ruby-rails-audit`.
   - **Cloud / Infra / Supply Chain:** `viper-aws-iam-cloud-audit`, `viper-gcp-azure-cloud-audit`, `viper-container-k8s-audit`, `viper-iac-terraform-audit`, `viper-cicd-hardening`, `viper-secrets-audit`, `viper-dependency-sbom`.
   - **AI / MCP Security:** `viper-ai-llm-redteam`, `viper-mcp-server-audit`, `viper-rag-vector-audit`.
3. **Phase 3 — Control Verification & Browser Hygiene (`viper-browseros-agent`, `viper_diff_oracle`):**
   - Verify cookie flags, storage hygiene, and access-control boundaries using `viper_diff_oracle` and BrowserOS Neo inspection.
4. **Phase 4 — 7-Gate Evidence Quality & CVSS Triage (`viper-proof-judge`):**
   - Validate every finding with `viper_verify_and_report` (`viperclaw verify`) to eliminate false positives and produce SARIF 2.1.0 + Markdown reports.
5. **Phase 5 — Root-Cause Remediation & Regression Tests (`viper-remediation-patch-verifier`):**
   - Synthesize minimal, idiomatic fixes paired with positive and negative regression tests, then re-run `viper_taint_scan` to confirm zero remaining unmitigated flows.
