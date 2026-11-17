---
name: viper-csrf-samesite-audit
description: Cross-Site Request Forgery (CSRF) Defense & State-Change Auditor (OWASP ASVS V4). Reviews anti-CSRF tokens, method semantics, SameSite cookies, and Origin/Sec-Fetch-Site verification.
---

# ViperClaw Skill 23: CSRF Defense & State-Change Auditor (`viper-csrf-samesite-audit`)

## Overview
Audits cookie-authenticated web applications and APIs to ensure all state-changing operations are protected against Cross-Site Request Forgery (CWE-352).

## Audit Checklist
1. **HTTP Method Semantics:** Confirm `GET` and `HEAD` routes are strictly read-only and never mutate account state, passwords, or permissions.
2. **Cryptographic Anti-CSRF Tokens:** Verify that `POST`/`PUT`/`PATCH`/`DELETE` forms and endpoints validate a session-bound CSRF token or require custom headers (`X-Requested-With` / JSON with preflight).
3. **Fetch Metadata & Origin Defense-in-Depth:** Validate `Sec-Fetch-Site` (`same-origin` / `same-site`), `Origin`, and `SameSite` cookie attributes alongside CSRF tokens.
