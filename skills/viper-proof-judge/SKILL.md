---
name: viper-proof-judge
description: Evidence Quality Gate, CVSS v3.1 Calculator & Security Report Writer. Validates diagnostic evidence, filters false positives, and generates SARIF 2.1.0 and Markdown audit reports.
---

# ViperClaw Skill 12: Evidence Quality Gate & Security Report Writer (`viper-proof-judge`)

## Overview
Uses `viper_verify_and_report` (`viperclaw verify`) to enforce the 7-Question Quality Gate, filter false positives (such as WAF challenge pages or non-security headers), compute CVSS v3.1 vectors, and generate structured reports.

## 7-Question Quality Gate
1. **Scope & Component:** Is the affected file or endpoint clearly identified?
2. **Non-WAF Verification:** Is the response a genuine application behavior rather than a CDN/WAF challenge page?
3. **Reproducible Evidence:** Are complete, non-destructive request/response or code-trace receipts included?
4. **Security Boundary Impact:** Does the issue cross a real trust boundary (confidentiality, integrity, or availability)?
5. **Actionable Severity:** Is the CVSS v3.1 vector mathematically consistent with the required privileges and impact?
6. **Root Cause Clarity:** Is the underlying CWE root cause explained clearly?
7. **Remediation Completeness:** Does the report include a concrete code or configuration fix?
