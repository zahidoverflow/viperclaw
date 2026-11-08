---
name: viper-auth-oauth-jwt
description: Authentication, OAuth 2.0 / OIDC, and JWT Exploitation Playbook. Targets redirect_uri parser bypasses, state fixation, JWT key confusion, and Account Takeover (ATO) chains.
---

# ViperClaw Auth, OAuth & JWT Hunter (`viper-auth-oauth-jwt`)

## 9 High-Payout Account Takeover (ATO) Vectors

### 1. OAuth 2.0 / OIDC Flaws
- **Unvalidated `redirect_uri` Subdomain / Path Traversal:** `redirect_uri=https://app.target.tld/callback/../../public/open-redirect` -> steals `code` or `access_token` via `Referer` or DOM leak.
- **Missing or Static `state` Parameter:** Cross-Site Request Forgery on `/oauth/callback` to link attacker's OAuth identity to victim's account.
- **Pre-Account Takeover (Unverified Email Claim):** Registering an unverified email +password account before the victim signs in via Google/SSO, when the backend merges accounts by email without checking `email_verified`.

### 2. JWT & Token Vulnerabilities
- **Unverified Signature / `alg: none`:** Strip signature and test if backend calls `jwt.decode(..., options={"verify_signature": False})`.
- **Key Confusion (`RS256` -> `HS256`):** Sign token using the server's public RSA key (from `/jwks.json` or `.well-known/openid-configuration`) as the HMAC secret.
- **`kid` / `jku` Header Injection:** Path traversal in `kid` (`../../../../dev/null` -> sign with empty string) or SSRF via `jku` pointing to an attacker-controlled JWKS file.
- **Cross-Tenant JWT Claim Tampering:** Valid JWT signature from Tenant B with modified body or query parameter `org_id=Tenant_A`.

### 3. Password Reset Poisoning
- `Host` / `X-Forwarded-Host` header injection during `POST /api/auth/forgot-password` causing reset links to point to an attacker domain.
