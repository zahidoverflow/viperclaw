---
name: viper-multitenant-isolation
description: Multi-Tenant SaaS Data Isolation & Row-Level Security (RLS) Auditor. Reviews tenant context propagation, ORM query scoping, shared cache keys, and background job isolation.
---

# ViperClaw Skill 28: Multi-Tenant SaaS Isolation & RLS Auditor (`viper-multitenant-isolation`)

## Overview
Audits multi-tenant SaaS architectures to prevent cross-tenant data leakage across databases, Redis caches, search indexes, and background worker queues.

## Audit Checklist
1. **Database Row-Level Security (RLS) & ORM Scoping:** Verify that every tenant-scoped table enforces `organization_id` / `tenant_id` filtering via PostgreSQL RLS policies or mandatory ORM repository scoping.
2. **Tenant-Prefixed Cache & Storage Keys:** Ensure Redis cache keys (`tenant:{tenant_id}:user:{id}`) and S3 object prefixes include the verified tenant identifier from the authenticated session.
3. **Async Job Context Integrity:** Confirm background jobs (Celery, BullMQ, Sidekiq) serialize and re-validate the tenant security context before executing bulk exports or notifications.
