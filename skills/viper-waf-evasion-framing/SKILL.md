---
name: viper-waf-evasion-framing
description: WAF Configuration, Parser Normalization & Filter Consistency Auditor. Reviews reverse-proxy vs. backend parser consistency, content-type validation, and input normalization.
---

# ViperClaw Skill 14: Reverse-Proxy & Parser Consistency Auditor (`viper-waf-evasion-framing`)

## Overview
Audits the boundary between upstream reverse proxies/WAFs (Cloudflare, Nginx, Envoy, AWS ALB) and downstream application frameworks (FastAPI, Express, Spring, Laravel) to eliminate parser differentials.

## Audit Checklist
1. **Content-Type & Schema Enforcement:** Ensure backend endpoints strictly enforce expected `Content-Type` headers (e.g., rejecting unexpected `text/xml` or `multipart/form-data` on JSON-only routes).
2. **Path & Parameter Normalization Consistency:** Verify that path parameters, duplicate query keys (HTTP Parameter Pollution), and JSON duplicate keys are normalized identically by both proxy middleware and application routers.
3. **Defense-in-Depth Remediation:** Never rely solely on perimeter WAF signature rules to block injection or access-control bugs—always fix the root cause in application code via parameterization and authorization middleware.
