---
name: viper-race-logic
description: Race Condition & Business Logic State-Machine Hunter. Targets TOCTOU limit overruns, single-packet HTTP/2 bursts, idempotency key flaws, and multi-step workflow skipping.
---

# ViperClaw Race Condition & Business Logic Hunter (`viper-race-logic`)

## Where Race Conditions Pay Critical Bounties
Look for any endpoint following a **Read-Check-Modify-Write** pattern without row-level locking (`SELECT ... FOR UPDATE`) or atomic database constraints:
- Redeeming single-use coupons, gift cards, or referral credits
- Transferring or withdrawing balances / loyalty points
- Inviting users beyond seat limits (`5/5 seats used`)
- Creating duplicate API keys or trial upgrades

## Single-Packet & Parallel Burst Methodology
1. **Identify the State Transition Request:** Locate the exact `POST`/`PUT` request that mutates state or consumes a quota.
2. **Synchronize 15–30 Concurrent Requests:**
   - On HTTP/2 targets, send all requests over a single connection warming up headers first and releasing the final byte simultaneously.
   - Vary non-semantic inputs if a WAF deduplicates identical bodies (`?v=1`, `?v=2`, whitespace padding in JSON, or distinct `X-Request-ID` headers).
3. **Verify Persistent State Overrun:**
   - Confirm that multiple `200 OK` / `201 Created` responses succeeded **and** that the resulting account balance, seat count, or coupon ledger reflects N>1 applications.
