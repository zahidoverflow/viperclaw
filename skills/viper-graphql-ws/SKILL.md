---
name: viper-graphql-ws
description: GraphQL Schema & WebSocket Security Auditor. Reviews introspection exposure, query depth/complexity limits, batching controls, and WebSocket origin/authentication checks.
---

# ViperClaw Skill 08: GraphQL Schema & WebSocket Security Auditor (`viper-graphql-ws`)

## Overview
Audits GraphQL servers and WebSocket handlers for schema exposure, resource exhaustion, and resolver-level authorization gaps.

## Audit Checklist
1. **Production Schema Hygiene:** Disable unauthenticated GraphQL introspection and verbose field-suggestion errors in production environments.
2. **Depth, Complexity & Batching Limits:** Configure maximum query depth, query cost/complexity limits, and bounded array/alias batching to prevent denial-of-service and rate-limit exhaustion.
3. **Resolver-Level Authorization & WebSocket Origin Checks:** Enforce authorization inside each GraphQL resolver/edge and validate `Origin` + session tokens during the WebSocket `Upgrade` handshake.
