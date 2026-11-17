---
name: viper-saml-sso-enterprise
description: Enterprise SAML 2.0, SCIM & XML Signature Wrapping (XSW) Auditor. Reviews SAML XML canonicalization, XSW assertion pinning, InResponseTo checks, and SCIM bearer auth.
---

# ViperClaw Skill 47: Enterprise SAML 2.0, SCIM & SSO Security Auditor (`viper-saml-sso-enterprise`)

## 1. Standards & Open-Source Reference
- **Standards:** OASIS SAML 2.0 Security Considerations, OWASP SAML Security Cheat Sheet, RFC 7644 (SCIM).
- **Focus:** Auditing SAML 2.0 Service Providers (SP), XML signature verification, and SCIM directory sync endpoints.

## 2. Rapid Discovery Patterns
- Search for `SAMLResponse`, `Assertion`, `validateSignature`, `wantAssertionsSigned`, `wantMessagesSigned`, `InResponseTo`, `/scim/v2/Users`.

## 3. Technical Audit Checklist
1. **XML Signature Wrapping (XSW) Prevention:** Verify that the SAML library validates the XML Digital Signature against the pinned IdP X.509 certificate *and* extracts the authenticated `NameID` / attributes **exclusively** from the exact DOM node referenced by the verified `<ds:Reference URI="#...">`, rejecting documents with multiple `<Assertion>` elements.
2. **XML Comments in `NameID` Canonicalization:** Ensure the SAML parser uses Exclusive XML Canonicalization *without comments* (`http://www.w3.org/2001/10/xml-exc-c14n#`) or reads `.textContent` after signature verification so `admin<!--comment-->@corp.com` cannot spoof `admin@corp.com`.
3. **Mandatory `Recipient`, `Audience`, `NotOnOrAfter` & `InResponseTo` Validation:** Reject assertions missing `AudienceRestriction` matching your SP EntityID, expired timestamps, or replayed `Assertion` IDs; disable IdP-initiated SSO or bind `InResponseTo` to a server-issued `AuthnRequest` ID.
4. **Multi-Tenant IdP Mapping Isolation:** In multi-tenant SaaS, verify that an assertion signed by **Tenant A's IdP certificate** can only authenticate users whose email domain belongs to **Tenant A** (preventing a rogue tenant admin from asserting `ceo@victim-tenant.com`).
5. **SCIM v2 Provisioning Endpoint Hardening:** Ensure `/scim/v2/Users` and `/scim/v2/Groups` validate tenant-scoped Bearer tokens, prevent cross-tenant `externalId` collisions, and immediately revoke active sessions when `active: false` is pushed via SCIM PATCH/PUT.

## 4. Vulnerable vs. Hardened Pattern
```python
# ❌ VULNERABLE: Accepts any tenant's IdP assertion for any email domain
idp_cert = get_idp_cert(request.form["tenant_slug"])
assertion = verify_saml_response(request.form["SAMLResponse"], idp_cert)
login_user_by_email(assertion.name_id)

# ✅ HARDENED: Enforces verified domain ownership binding between Tenant IdP and NameID
tenant = get_tenant_by_slug(request.form["tenant_slug"])
assertion = verify_saml_response(
    request.form["SAMLResponse"],
    cert=tenant.idp_x509_cert,
    expected_audience=SP_ENTITY_ID,
    expected_recipient=SP_ACS_URL,
)
email_domain = assertion.name_id.split("@")[-1].lower()
if email_domain not in tenant.verified_domains:
    raise PermissionError("IdP is not authorized to assert identities for this domain")
```
