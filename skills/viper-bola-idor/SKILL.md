---
name: viper-bola-idor
description: Cross-Tenant Authorization (BOLA / IDOR / BFLA) Hunting Playbook. Builds a multi-role authorization matrix, mutates resource identifiers, and validates leaks via the Differential Oracle.
---

# ViperClaw BOLA / IDOR / BFLA Hunter (`viper-bola-idor`)

## Core Rule
Never report an IDOR without proving a **cross-tenant differential** between at least two distinct security contexts (Tenant A vs. Tenant B) and verifying that the response is not public data or a WAF soft-block.

## 5-Step Kill Chain

1. **Build the Role Matrix:**
   Prepare credentials/tokens for:
   - `Role_A` (Victim Tenant / User A)
   - `Role_B` (Attacker Tenant / User B)
   - `Unauth` (No cookies / stripped `Authorization` header)
2. **Harvest Object Reference Endpoints:**
   Pull top `idor_candidates` from `viperclaw harvest-js` or `.viperclaw/graph.db`.
3. **Execute Cross-Tenant Replay (`Role_B` token + `Role_A` object ID):**
   Test read (`GET`), state mutation (`PUT`/`PATCH`/`POST`), and deletion (`DELETE`) across sub-routes (`/api/v2/orgs/{id}/members`, `/export`, `/invoices`).
4. **Apply Identifier Evasion & Parameter Pollution:**
   - Numeric IDs (`1001` -> `1000`)
   - UUID v1/v4 swaps or wildcard (`*`)
   - Array wrapping (`{"id": [victim_id]}`)
   - HTTP Parameter Pollution (`?user_id=attacker&user_id=victim`)
   - API version downgrade (`/api/v3/orders` -> `/api/v1/orders`)
5. **Verify via Differential Oracle (`viper_diff_oracle`):**
   Confirm `baseline_status == 200`, `probe_status == 200`, high structural JSON key overlap, and `unauth_status in (401, 403, 404)`.
