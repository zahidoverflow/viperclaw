---
name: viper-dns-email-domain
description: DNS, Subdomain Takeover, SPF/DKIM/DMARC & Email Security Auditor. Reviews dangling CNAME/NS records, SPF lookup limits, DMARC p=reject, and SMTP/Host header injection.
---

# ViperClaw Skill 55: DNS, Subdomain Takeover & Email Security Auditor (`viper-dns-email-domain`)

## 1. Standards & Open-Source Reference
- **Standards:** `EdOverflow/can-i-take-over-xyz`, RFC 7208 (SPF), RFC 6376 (DKIM), RFC 7489 (DMARC), OWASP Password Reset Cheat Sheet.
- **Focus:** Auditing DNS zone files (Terraform Route53/Cloudflare), email authentication records, and transactional email templates.

## 2. Rapid Discovery Patterns
- Search IaC / DNS configs for `CNAME`, `aws_route53_record`, `cloudflare_record`, `v=spf1`, `v=DMARC1`.
- Search application code for `sendmail`, `smtplib`, `Reply-To`, `request.host`, `X-Forwarded-Host`.

## 3. Technical Audit Checklist
1. **Dangling DNS & Subdomain Takeover Prevention:** Audit all `CNAME`, `ALIAS`, and `NS` records pointing to external cloud providers (`*.s3.amazonaws.com`, `*.azurewebsites.net`, `*.github.io`, `*.herokuapp.com`, `*.cloudfront.net`, `*.fastly.net`) to confirm the target resource is actively claimed, and delete DNS records *before* deprovisioning cloud resources.
2. **SPF, DKIM & DMARC Enforcement:** Verify the root domain and all mail-sending subdomains publish an SPF record ending with hard-fail `-all` (within the 10-DNS-lookup RFC limit), 2048-bit RSA / Ed25519 DKIM keys, and a DMARC record with `v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s;`.
3. **Password Reset Host-Header Poisoning Prevention:** Never generate password-reset, magic-link, or invitation URLs using `request.headers["Host"]` or `X-Forwarded-Host`; always construct links using a pinned `APP_BASE_URL` configuration constant.
4. **SMTP Header & Template Injection:** Strip `` and `
` from user-supplied `Subject`, `From`, `Reply-To`, and recipient display names, and never pass user input into email template syntax before rendering.
5. **CAA (Certification Authority Authorization) Records:** Configure DNS `CAA` records restricting TLS certificate issuance to your organization's approved Certificate Authorities (e.g., `0 issue "letsencrypt.org"`).

## 4. Vulnerable vs. Hardened Pattern
```python
# ❌ VULNERABLE: Password reset link uses untrusted HTTP Host header (Host Header Poisoning)
reset_url = f"https://{request.headers.get('Host')}/reset?token={token}"

# ✅ HARDENED: Uses pinned canonical base URL from immutable server config
reset_url = f"{settings.CANONICAL_BASE_URL}/reset?token={token}"
```
