---
name: viper-proof-judge
description: Zero-Context Adversarial QA Judge, 7-Question Triage Gate, CVSS 3.1 Calculator, and Bug Bounty / SARIF Report Writer. Ensures zero false positives before any finding is reported.
---

# ViperClaw Adversarial Proof Judge (`viper-proof-judge`)

## The Zero-Hallucination Law
**No Receipt, No Report.** Before presenting any vulnerability to the operator or writing a final report, you MUST pass the candidate finding through `viperclaw verify` (or the `viper_verify_and_report` MCP tool).

## The 7-Question Pre-Submission Gate
1. **Not Scanner Noise:** Is it free of always-rejected fluff (missing headers, SPF/DMARC, self-XSS, theoretical CORS)?
2. **In Scope:** Is the exact hostname/repo confirmed inside authorized scope?
3. **Request Receipt:** Is the exact, unedited HTTP request or reproduction command included?
4. **Valid Response Receipt:** Is the raw response included, and has `ProofOracle.detect_waf_soft_block` confirmed it is NOT a Cloudflare/Akamai/CloudFront block page?
5. **Cross-Boundary Proof:** Does it cross a real authentication or tenant boundary (e.g., User B accessing User A's resource)?
6. **Non-Theoretical Impact:** Have all speculative phrases (*"could potentially"*, *"might allow"*) been replaced with proven CIA impact?
7. **CVSS Threshold:** Is the CVSS 3.1 score `>= 4.0` (or chained with another gadget to reach Medium/High/Critical)?

## Command Usage
```bash
viperclaw verify \
  --title "Cross-Tenant BOLA on /api/v2/invoices/{id} Exposes Customer Billing PII" \
  --vuln-class "Broken Object Level Authorization (CWE-639)" \
  --asset "https://api.example.com/api/v2/invoices/1042" \
  --request "GET /api/v2/invoices/1042 HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer <TENANT_B_TOKEN>" \
  --response "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{"invoice_id":1042,"tenant_id":"tenant_a","ssn_last4":"8821"}" \
  --sarif-out findings.sarif
```
