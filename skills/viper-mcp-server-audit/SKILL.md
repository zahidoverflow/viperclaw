---
name: viper-mcp-server-audit
description: Model Context Protocol (MCP) Server & Agentic Tool Security Auditor (OWASP MCP Top 10). Audits tool schemas, Rug Pull mutation defenses, stdio sandboxing, and HITL gates.
---

# ViperClaw Skill 35: Model Context Protocol (MCP) Server Security Auditor (`viper-mcp-server-audit`)

## 1. Standards & Open-Source Reference
- **Standards:** OWASP MCP Top 10, OWASP Top 10 for Agentic Applications (ASI01–ASI10), CWE-78, CWE-22, CWE-269.
- **Focus:** Auditing local (`stdio`) and remote (`SSE` / Streamable HTTP) MCP servers, tool schemas, and agent host integrations.

## 2. Rapid Discovery Patterns
- Search for MCP tool registrations: `@mcp.tool`, `server.setRequestHandler(CallToolRequestSchema`, `tools/list`, `inputSchema`.
- Search for shell/filesystem sinks inside tool handlers: `subprocess`, `child_process.exec`, `os.system`, `fs.readFile`, `open(`.

## 3. Technical Audit Checklist
1. **Strict Input Schema Enforcement:** Every MCP tool must define a strict JSON Schema (`additionalProperties: false`, explicit `enum` or regex patterns, and bounded string lengths) and validate arguments before execution.
2. **Command & Path Sandboxing (`stdio` Servers):** Never pass tool arguments into `shell=True` or unvalidated filesystem paths; canonicalize paths with `Path.resolve()` and enforce an explicit workspace root prefix check.
3. **Tool Poisoning & Prompt-In-Description Defense:** Audit tool `description` fields and returned tool output blocks to ensure untrusted external data cannot inject instructions that hijack sibling MCP servers.
4. **Remote MCP Transport Authentication:** Remote HTTP/SSE MCP endpoints must validate OAuth 2.1 Bearer tokens with audience (`aud`) binding, mTLS, and strict `Origin` header checks to prevent local DNS-rebinding or CSRF calls.
5. **Human-in-the-Loop (HITL) Confirmation:** State-changing, network-egress, or destructive tools must declare destructive annotations and require explicit user approval showing exact resolved arguments.

## 4. Vulnerable vs. Hardened Pattern
```python
# ❌ VULNERABLE: Unchecked path & shell interpolation in MCP tool
def read_log(filename: str) -> str:
    return subprocess.check_output(f"tail -n 50 /var/log/app/{filename}", shell=True).decode()

# ✅ HARDENED: Canonicalized workspace boundary & zero-shell reading
ALLOWED_DIR = Path("/var/log/app").resolve()
def read_log(filename: str) -> str:
    target = (ALLOWED_DIR / filename).resolve()
    if not target.is_relative_to(ALLOWED_DIR) or not target.is_file():
        raise ValueError("Access denied: path outside allowed log directory")
    lines = target.read_text(encoding="utf-8", errors="replace").splitlines()
    return "\n".join(lines[-50:])
```
