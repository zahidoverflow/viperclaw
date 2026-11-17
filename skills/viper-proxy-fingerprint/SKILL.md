---
name: viper-proxy-fingerprint
description: HTTP Stack, Header & Error-Envelope Auditor. Reviews HAR captures and HTTP responses to inventory backend frameworks, cookie security attributes, and verbose error disclosures.
---

# ViperClaw Skill 03: HTTP Stack & Error-Envelope Auditor (`viper-proxy-fingerprint`)

## Overview
Analyzes `.har` captures and HTTP response metadata (`viper_fingerprint_traffic`) to evaluate server header hygiene, framework configuration, and error-handling consistency.

## Audit Checklist
1. **Information Disclosure Review:** Identify verbose `Server`, `X-Powered-By`, and stack-trace error responses in production environments.
2. **Authentication & Cookie Hygiene:** Check that session cookies enforce `HttpOnly`, `Secure`, and `SameSite=Lax`/`Strict`.
3. **Error Envelope Standardization:** Ensure API errors return uniform, non-sensitive status envelopes without leaking internal database or file paths.
