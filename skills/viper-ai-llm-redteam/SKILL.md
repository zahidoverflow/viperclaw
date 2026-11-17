---
name: viper-ai-llm-redteam
description: AI, LLM & MCP Application Security Auditor (OWASP LLM Top 10). Reviews prompt construction, RAG data boundaries, tool-call authorization, and output handling.
---

# ViperClaw Skill 11: AI, LLM & MCP Application Security Auditor (`viper-ai-llm-redteam`)

## Overview
Audits LLM-integrated applications, RAG pipelines, and Model Context Protocol (MCP) tool servers against the OWASP Top 10 for LLM Applications.

## Audit Checklist
1. **System Prompt & Trust Boundary Separation:** Ensure system instructions never contain hardcoded credentials or secrets, and untrusted user/RAG content is clearly delimited from control instructions.
2. **Least-Privilege Tool Calling (Human-in-the-Loop):** Require explicit user confirmation and strict JSON schema validation before executing state-changing or external-network MCP/function tools.
3. **Output Sanitization:** Treat all LLM-generated output as untrusted data—sanitize HTML/Markdown before rendering in the DOM and parameterize any downstream database or shell calls.
