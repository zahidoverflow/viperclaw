---
name: viper-bola-idor
description: Object & Function-Level Authorization (BOLA / BFLA) Audit Skill. Reviews resource access controls, tenant scoping, and ownership checks across API endpoints and controllers.
---

# ViperClaw Skill 04: Authorization & Tenant Isolation Auditor (`viper-bola-idor`)

## Overview
Audits API controllers, database queries, and middleware to ensure every resource lookup enforces explicit caller ownership and tenant scoping (OWASP API1:2023 / API5:2023).

## Audit Checklist
1. **Controller Ownership Binding:** Verify that object lookups (`SELECT ... WHERE id = ?`) also bind the authenticated `user_id` or `tenant_id` from the session context.
2. **Function-Level RBAC Review:** Confirm administrative and state-changing routes enforce role-based middleware checks before executing business logic.
3. **Differential Response Verification:** Use `viper_diff_oracle` to compare authorized vs. unauthorized baseline responses and confirm `403 Forbidden` / `404 Not Found` enforcement.
