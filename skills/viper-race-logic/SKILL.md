---
name: viper-race-logic
description: Concurrency, Idempotency & Business Logic Auditor. Reviews state-changing transactions, database locking, and multi-step workflow integrity to prevent TOCTOU race conditions.
---

# ViperClaw Skill 09: Concurrency, Idempotency & Business Logic Auditor (`viper-race-logic`)

## Overview
Audits financial transfers, coupon redemptions, quota checks, and multi-step state machines for Time-of-Check to Time-of-Use (TOCTOU) concurrency flaws (CWE-362).

## Audit Checklist
1. **Atomic Database Operations:** Replace separate read-then-write checks with atomic conditional updates (`UPDATE ... WHERE balance >= :amount`) or `SELECT ... FOR UPDATE` row locks inside a serializable transaction.
2. **Idempotency Keys & Distributed Locks:** Enforce unique idempotency keys and database uniqueness constraints on one-time redemptions and payment operations.
3. **Sequential Workflow State Enforcement:** Verify server-side session state at every step of a multi-stage workflow so mandatory verification steps cannot be skipped.
