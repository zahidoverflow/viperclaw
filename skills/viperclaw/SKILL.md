---
name: viperclaw
description: Master ViperClaw Security Audit entrypoint (`/viperclaw`). Launches the 5-phase Security Audit Orchestrator, maps trust boundaries in `.viperclaw/graph.db`, runs multi-language taint SAST, SPA bundle harvesting, and 7-Gate Proof Oracle verification across all 64 specialized ViperClaw skills.
---

# ViperClaw Master Security Audit Entrypoint (`/viperclaw`)

Use this skill whenever the user invokes `/viperclaw` or requests a comprehensive security audit, code review, or bug-bounty-grade verification using ViperClaw.

## 5-Phase Execution Plan

1. **Phase 1 — Surface & Dependency Inventory (`viper-orchestrator`, `viper-threat-model-stride`):**
   - Run `viperclaw taint . --db .viperclaw/graph.db` and `viperclaw harvest-js . --db .viperclaw/graph.db`.
   - Identify frameworks, entrypoints, cloud IaC (`Dockerfile`, `*.tf`, `.github/workflows/*.yml`), and trust boundaries.
2. **Phase 2 — Domain-Specific Skill Routing (64 Specialized Playbooks):**
   - **Web / API:** `viper-bola-idor`, `viper-injection-oracle`, `viper-ssrf-cloud`, `viper-auth-oauth-jwt`, `viper-graphql-ws`, `viper-race-logic`, `viper-openapi-rest-schema`.
   - **Stacks:** `viper-nextjs-react-rsc`, `viper-fastapi-django-flask`, `viper-nodejs-express-nestjs`, `viper-go-service-audit`, `viper-rust-memory-unsafe`, `viper-java-spring-audit`, `viper-php-laravel-wordpress`, `viper-ruby-rails-audit`.
   - **Cloud / Infra / CI:** `viper-aws-iam-cloud-audit`, `viper-gcp-azure-cloud-audit`, `viper-container-k8s-audit`, `viper-iac-terraform-audit`, `viper-cicd-hardening`, `viper-secrets-audit`.
   - **AI / MCP:** `viper-ai-llm-redteam`, `viper-mcp-server-audit`, `viper-rag-vector-audit`.
3. **Phase 3 — Live Verification & Browser Inspection (`viper-browseros-agent`, `viper_diff_oracle`):**
   - Use `viper_diff_oracle` and BrowserOS Neo (`viper_browser_ingest`) to verify controls non-destructively.
4. **Phase 4 — 7-Gate Proof Oracle (`viper-proof-judge`):**
   - Validate every finding with `viper_verify_and_report` (`viperclaw verify`) to eliminate false positives and compute exact CVSS v3.1 vectors.
5. **Phase 5 — Root-Cause Remediation & Regression Tests (`viper-remediation-patch-verifier`):**
   - Produce minimal, idiomatic fixes paired with positive and negative unit tests, then re-run `viperclaw taint` to verify `0` remaining flows.
