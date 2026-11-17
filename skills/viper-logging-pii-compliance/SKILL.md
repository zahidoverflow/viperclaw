---
name: viper-logging-pii-compliance
description: Security Logging, PII Redaction & Error Sanitization Auditor (OWASP Logging Cheat Sheet & ASVS V7). Reviews audit trail coverage, log injection defenses, and secret scrubbing.
---

# ViperClaw Skill 31: Security Logging, PII Redaction & Audit Trail Skill (`viper-logging-pii-compliance`)

## Overview
Audits application logging, telemetry pipelines, and exception handlers to ensure critical security events are recorded without leaking credentials or PII (CWE-532, CWE-117).

## Audit Checklist
1. **Sensitive Data Redaction:** Configure structured log processors to automatically redact `Authorization` headers, `Cookie` values, `password`, `token`, `secret`, `cvv`, and SSN fields before writing to logs or Sentry/Datadog.
2. **Log Injection Prevention:** Use structured JSON logging rather than raw string concatenation, and strip CR/LF (`\r\n`) control characters from user-controlled log fields.
3. **Security Event Coverage:** Verify that authentication failures, privilege changes, MFA resets, API key creations, and access-control denials emit tamper-evident audit events with actor, timestamp, and correlation ID.
