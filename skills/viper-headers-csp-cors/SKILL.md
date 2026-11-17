---
name: viper-headers-csp-cors
description: HTTP Security Headers, Content-Security-Policy (CSP) & CORS Configuration Auditor (modeled on Mozilla Observatory & OWASP Secure Headers). Reviews origin reflection and framing defenses.
---

# ViperClaw Skill 20: HTTP Headers, CSP & CORS Configuration Auditor (`viper-headers-csp-cors`)

## Overview
Audits web server and API middleware configurations for CORS misconfigurations, weak Content-Security-Policy (CSP) directives, and missing browser defense headers.

## Audit Checklist
1. **CORS Origin Validation:** Never reflect arbitrary `Origin` headers or allow `Origin: null` when `Access-Control-Allow-Credentials: true` is set; validate against a strict, exact-match origin allowlist.
2. **Content-Security-Policy (CSP):** Avoid `'unsafe-inline'`, `'unsafe-eval'`, and overly broad wildcard sources (`*`, `data:`) in `script-src`; prefer nonce- or hash-based policies with `object-src 'none'` and `base-uri 'self'`.
3. **Standard Defense Headers:** Enforce `Strict-Transport-Security` (HSTS), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` (or CSP `frame-ancestors`), and `Referrer-Policy`.
