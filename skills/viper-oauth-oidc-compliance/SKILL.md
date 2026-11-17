---
name: viper-oauth-oidc-compliance
description: OAuth 2.1, OIDC & SSO Protocol Compliance Auditor (RFC 9700 / OAuth Security Best Current Practice). Reviews PKCE S256, state/nonce binding, token audience, and SAML XML signature wrapping.
---

# ViperClaw Skill 33: OAuth 2.1, OIDC & SSO Protocol Compliance Auditor (`viper-oauth-oidc-compliance`)

## Overview
Audits OAuth 2.0 / 2.1 clients, Authorization Servers, OpenID Connect (OIDC) Relying Parties, and SAML 2.0 Service Providers against RFC 9700 (OAuth 2.0 Security Best Current Practice).

## Audit Checklist
1. **PKCE (`S256`) & `state` Enforcement:** Require Proof Key for Code Exchange (`code_challenge_method=S256`) and cryptographically bound `state` + OIDC `nonce` parameters on all authorization code flows.
2. **Strict `redirect_uri` & Token Leakage Prevention:** Enforce exact character-by-character `redirect_uri` matching (no wildcards or open-redirect chaining) and disable legacy Implicit (`response_type=token`) flows.
3. **OIDC / SAML Assertion Validation:** Verify `iss`, `aud`, `exp`, and `email_verified === true` on OIDC ID tokens, and ensure SAML parsers validate XML signatures against pinned IdP certificates before reading assertion attributes.
