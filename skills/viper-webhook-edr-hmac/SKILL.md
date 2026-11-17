---
name: viper-webhook-edr-hmac
description: Inbound & Outbound Webhook Security Auditor. Reviews HMAC-SHA256 signature verification, constant-time comparison, timestamp replay windows, and mutual TLS.
---

# ViperClaw Skill 27: Inbound & Outbound Webhook Security Auditor (`viper-webhook-edr-hmac`)

## Overview
Audits webhook receivers (Stripe, GitHub, Slack, custom payment callbacks) and outbound webhook delivery systems for spoofing, replay, and SSRF risks.

## Audit Checklist
1. **Cryptographic Signature Verification:** Verify webhook signatures over the raw request body bytes using `hmac.compare_digest` (constant-time comparison) before parsing or processing the event.
2. **Timestamp & Replay Protection:** Validate the webhook timestamp header (e.g., within a 5-minute tolerance window) and track processed `event_id` values in a cache/database to prevent replay.
3. **Outbound Delivery Isolation:** Dispatch outbound user-configured webhooks asynchronously via an isolated egress worker that blocks internal RFC 1918 and cloud metadata IPs.
