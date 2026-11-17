---
name: viper-webauthn-passkey-mfa
description: WebAuthn, FIDO2 Passkey & TOTP MFA Security Auditor. Reviews challenge single-use binding, rpId/origin validation, signCount clone detection, userVerification, and step-up MFA.
---

# ViperClaw Skill 46: WebAuthn, FIDO2 Passkey & MFA Security Auditor (`viper-webauthn-passkey-mfa`)

## 1. Standards & Open-Source Reference
- **Standards:** W3C WebAuthn Level 2/3 Specification, OWASP Multifactor Authentication Cheat Sheet, NIST SP 800-63B.
- **Focus:** Auditing FIDO2/WebAuthn passkey registration & authentication flows, TOTP/recovery codes, and MFA session step-up logic.

## 2. Rapid Discovery Patterns
- Search for `verifyRegistrationResponse`, `verifyAuthenticationResponse`, `clientDataJSON`, `expectedOrigin`, `expectedRPID`, `userVerification`, `totp.verify`.

## 3. Technical Audit Checklist
1. **Single-Use Server-Stored Challenge Binding:** The WebAuthn `challenge` must be >= 16 bytes of CSPRNG output, stored in the server-side session/cache bound to the specific `user_id` with a short TTL (e.g., 5 minutes), and **deleted atomically** upon the first verification attempt.
2. **Strict `expectedOrigin` & `expectedRPID` Pinning:** Never derive `expectedOrigin` or `expectedRPID` dynamically from the incoming `Origin` or `Host` HTTP request header; compare against a hardcoded configuration constant.
3. **Mandatory `userVerification: "required"` for Passwordless Flows:** When passkeys act as a single-factor password replacement, enforce `userVerification: "required"` (UV flag checked in `authenticatorData`) so a stolen physical security key cannot authenticate without biometrics/PIN.
4. **Clone Detection (`signCount`) & TOTP Replay Prevention:** Update the stored credential `signCount` on each login and alert/revoke if `newSignCount <= storedSignCount` (when `signCount > 0`); for TOTP, record the last used 30-second time step per user so a 6-digit code cannot be replayed within the same window.
5. **Server-Side MFA State Binding:** Never issue a full session token after step 1 (password check) expecting the frontend to redirect to `/mfa`; issue a restricted, short-lived `pre_mfa_token` that is only valid on `/api/mfa/verify`.

## 4. Vulnerable vs. Hardened Pattern
```typescript
// ❌ VULNERABLE: Trusts client-supplied challenge & Origin header without deleting challenge
const verification = await verifyAuthenticationResponse({
  response: req.body,
  expectedChallenge: req.body.challenge,
  expectedOrigin: req.headers.origin,
  expectedRPID: req.hostname,
  authenticator,
});

// ✅ HARDENED: Consumes server-stored challenge atomically & pins RPID/Origin + requireUserVerification
const expectedChallenge = await redis.getDel(`webauthn:chal:${session.userId}`);
if (!expectedChallenge) throw new UnauthorizedError("Expired or missing challenge");
const verification = await verifyAuthenticationResponse({
  response: req.body,
  expectedChallenge,
  expectedOrigin: "https://login.example.com",
  expectedRPID: "example.com",
  requireUserVerification: true,
  authenticator,
});
```
