---
name: viper-openapi-rest-schema
description: OpenAPI / Swagger Schema, Mass Assignment & REST API Security Auditor (OWASP API3 & API4). Reviews DTO allowlisting, pagination caps, and schema validation.
---

# ViperClaw Skill 26: OpenAPI Schema, Mass Assignment & REST API Auditor (`viper-openapi-rest-schema`)

## Overview
Audits REST API controllers, Pydantic/Zod/DTO schemas, and OpenAPI v3 specifications against OWASP API3:2023 (Broken Object Property Level Authorization) and API4:2023.

## Audit Checklist
1. **Mass Assignment Prevention:** Never bind raw request bodies (`req.body`, `**request.json`) directly to ORM models (`User.update(**data)`). Use explicit input DTOs that exclude `role`, `is_admin`, `balance`, and `tenant_id`.
2. **Response Data Minimization:** Use explicit output serializer schemas so internal fields (`password_hash`, `mfa_secret`, `internal_notes`) are never serialized in API responses.
3. **Pagination & Resource Bounds:** Enforce strict upper bounds on `limit` / `page_size` parameters (e.g., `max_limit = 100`) and request body byte sizes.
