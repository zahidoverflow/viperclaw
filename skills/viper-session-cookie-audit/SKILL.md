---
name: viper-session-cookie-audit
description: Session Lifecycle, Cookie Hardening & Token Invalidation Auditor (OWASP ASVS V3). Reviews session fixation defenses, absolute/idle timeouts, and server-side revocation.
---

# ViperClaw Skill 22: Session Lifecycle & Cookie Security Auditor (`viper-session-cookie-audit`)

## Overview
Audits session management implementations against OWASP ASVS V3 (Session Management) to prevent session hijacking, fixation, and post-logout reuse.

## Audit Checklist
1. **Session Regeneration on Privilege Change:** Regenerate the session identifier upon login, privilege elevation, or password reset to prevent session fixation.
2. **Server-Side Revocation:** Ensure logout, password change, and MFA reset immediately invalidate active session records or refresh tokens on the server.
3. **Cookie Attributes & Prefixes:** Set `Secure`, `HttpOnly`, `SameSite=Lax` (or `Strict`), and consider `__Host-` cookie prefixes for high-value session cookies.
