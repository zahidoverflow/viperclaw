---
name: viper-rate-limit-dos-resilience
description: Application Rate Limiting, ReDoS & Resource Exhaustion Auditor (OWASP API4:2023). Reviews brute-force protections, regular expression complexity, and payload/decompression limits.
---

# ViperClaw Skill 32: Rate Limiting, ReDoS & Resource Resilience Auditor (`viper-rate-limit-dos-resilience`)

## Overview
Audits authentication endpoints, search/export routes, regular expressions, and file parsers against resource exhaustion and denial-of-service weaknesses (CWE-400, CWE-1333).

## Audit Checklist
1. **Endpoint & Account Rate Limiting:** Enforce sliding-window or token-bucket rate limits keyed by both IP and account identifier on login, OTP/MFA verification, password reset, and expensive export/AI routes.
2. **Regular Expression Complexity (ReDoS):** Audit regex patterns for nested quantifiers (`(a+)+`, `([a-zA-Z]+)*`) evaluated against untrusted input, or use linear-time regex engines (`re2`).
3. **Payload & Decompression Quotas:** Configure explicit maximum request body sizes, JSON nesting depth limits, and decompression byte caps (zip-bomb protection).
