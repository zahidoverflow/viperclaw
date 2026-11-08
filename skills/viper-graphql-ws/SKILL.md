---
name: viper-graphql-ws
description: GraphQL & WebSocket Security Audit Skill. Covers introspection bypass, field clairvoyance, alias batching, field-level BOLA, Cross-Site WebSocket Hijacking (CSWSH), and subscription IDOR.
---

# ViperClaw GraphQL & WebSocket Auditor (`viper-graphql-ws`)

## Part 1: GraphQL Exploitation Playbook

1. **Discovery & Introspection Bypass:**
   - Probe `/graphql`, `/api/graphql`, `/v1/graphql`, `/gql`.
   - If `__schema` is blocked, test newline/whitespace injection (`__schema
{types{name}}`), `GET` query parameter execution, or harvest client queries directly from JS bundles using `viperclaw harvest-js`.
2. **Field Suggestion Clairvoyance:**
   - Send intentional typos (`query { user { passwor } }`) to harvest `Did you mean "passwordResetToken"?` suggestions from Apollo/GraphQL-js.
3. **Field-Level Authorization (BOLA in GraphQL Edges):**
   - Even if `query { user(id: "victim") }` is blocked at the root resolver, traverse nested edges:
     ```graphql
     query {
       myOrganization {
         projects {
           owner { email apiKey }
         }
       }
     }
     ```
4. **Alias Batching Rate-Limit Bypass:**
   - Pack 100 OTP/login mutations into a single HTTP request using GraphQL aliases (`m1: verifyOtp(code:"0001")`, `m2: verifyOtp(code:"0002")`).

## Part 2: WebSocket (`ws://` / `wss://`) Playbook
1. **Cross-Site WebSocket Hijacking (CSWSH):** Replay the `Upgrade: websocket` handshake with `Origin: https://attacker.example` when auth relies on cookies.
2. **Subscription IDOR:** Subscribe to another tenant's real-time channel (`{"type": "subscribe", "channel": "org_1001_events"}`) after authenticating as `org_1002`.
