---
name: viper-privacy-gdpr-hipaa
description: Privacy Engineering, GDPR / HIPAA Data Flow & PII Minimization Auditor. Reviews PII/PHI inventory, field-level encryption, right-to-erasure cascades, and analytics leaks.
---

# ViperClaw Skill 60: Privacy Engineering, GDPR / HIPAA & PII Data Flow Auditor (`viper-privacy-gdpr-hipaa`)

## 1. Standards & Open-Source Reference
- **Standards:** GDPR Articles 17/25/32, HIPAA Security Rule, OWASP Top 10 Privacy Risks, LINDDUN Privacy Threat Modeling.
- **Focus:** Auditing PII/PHI collection, storage encryption, deletion cascades, URL query parameters, and third-party SDK data sharing.

## 2. Rapid Discovery Patterns
- Search models and schemas for `email`, `phone`, `ssn`, `dob`, `date_of_birth`, `ip_address`, `tax_id`, `medical`, `location`.
- Check URL parameters, analytics calls (`gtag(`, `segment.track`, `mixpanel.track`), and account deletion handlers.

## 3. Technical Audit Checklist
1. **No PII/PHI in URL Query Strings:** Never pass email addresses, phone numbers, names, session tokens, or reset codes in `GET` query parameters (`?email=user@example.com`), as URLs are leaked via `Referer` headers, browser history, and proxy/CDN access logs.
2. **Application-Layer Field Encryption & Blind Indexing:** Encrypt high-sensitivity PII/PHI (SSN, tax IDs, health records, biometric templates) at the application layer using envelope encryption (AEAD `AES-256-GCM` with KMS data keys) and use keyed HMAC-SHA256 blind indexes if exact-match lookup is required.
3. **Complete Right-to-Erasure (GDPR Art. 17) Cascade:** Audit user deletion workflows (`delete_account`) to ensure PII is purged or irreversibly anonymized across primary tables, search indexes (Elasticsearch/Algolia), vector stores, Redis caches, and S3 exports.
4. **Third-Party Analytics & LLM Egress Scrubbing:** Verify that frontend analytics SDKs (Google Analytics, PostHog, Segment, Sentry) and external LLM API calls scrub PII/PHI and respect user consent flags before transmitting events.
5. **Data Retention & Automated TTL Purging:** Enforce explicit retention TTL policies on raw audit logs, IP addresses, session tables, and temporary file exports.

## 4. Vulnerable vs. Hardened Pattern
```python
# ❌ VULNERABLE: Soft-deletes user flag but leaves plaintext PII, sessions & search index intact
def delete_account(user_id: int):
    db.execute("UPDATE users SET deleted_at = NOW() WHERE id = %s", [user_id])

# ✅ HARDENED: Scrubs PII, revokes active sessions, and purges secondary search/cache stores
def delete_account(user_id: int):
    with db.transaction():
        db.execute(
            "UPDATE users SET email = %s, name = 'Deleted User', phone = NULL, pii_blob = NULL, deleted_at = NOW() WHERE id = %s",
            [f"deleted-{user_id}@anonymized.invalid", user_id],
        )
        db.execute("DELETE FROM user_sessions WHERE user_id = %s", [user_id])
    search_index.delete_document(f"user:{user_id}")
    redis_cache.delete(f"user_profile:{user_id}")
```
