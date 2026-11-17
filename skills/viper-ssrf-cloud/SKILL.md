---
name: viper-ssrf-cloud
description: Outbound Request (SSRF) & Cloud Egress Auditor. Reviews URL-fetching logic, webhook dispatchers, and cloud instance metadata (IMDSv2) protections.
---

# ViperClaw Skill 06: Outbound Request & Cloud Egress Auditor (`viper-ssrf-cloud`)

## Overview
Audits server-side HTTP clients, webhook testers, and media importers to prevent Server-Side Request Forgery (CWE-918) and protect cloud metadata services.

## Audit Checklist
1. **URL Parsing & Allowlisting:** Verify that outbound URLs are parsed strictly (`https` scheme only) and validated against an explicit domain allowlist.
2. **DNS Resolution & Private CIDR Filtering:** Ensure the HTTP client resolves the hostname and rejects loopback (`127.0.0.0/8`), RFC 1918 private ranges, and link-local metadata IPs (`169.254.169.254`) before connecting and on every redirect hop.
3. **Cloud IMDSv2 Hardening:** Confirm cloud instances enforce session-oriented IMDSv2 (`HttpTokens=required`, hop limit `1`) and least-privilege IAM roles.
