---
name: viper-auth-oauth-jwt
description: Authentication, OAuth 2.0 / OIDC & JWT Security Auditor. Reviews token verification, algorithm allowlisting, claim validation, and OAuth redirect_uri configurations.
---

# ViperClaw Skill 07: Authentication, OAuth 2.0 & JWT Security Auditor (`viper-auth-oauth-jwt`)

## Overview
Audits JWT verification middleware, OAuth 2.0 / OIDC flows, and account lifecycle endpoints to ensure RFC-compliant authentication security.

## Audit Checklist
1. **Explicit JWT Algorithm Allowlisting:** Verify that JWT decoders explicitly specify the expected algorithm (e.g., `algorithms=["RS256"]`), reject `none`, and never use public keys as symmetric HMAC secrets.
2. **Claim & Expiration Enforcement:** Ensure `exp`, `nbf`, `iss`, and `aud` claims are mandatory and validated on every request, and signing secrets have high cryptographic entropy.
3. **OAuth 2.0 / OIDC Hardening:** Confirm exact match validation on `redirect_uri`, mandatory `state` / PKCE (`S256`) binding, and verified email checks prior to account linking.
