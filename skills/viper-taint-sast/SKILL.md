---
name: viper-taint-sast
description: White-Box Multi-Language Source-to-Sink Taint Analysis Skill. Traces untrusted inputs to sensitive sinks across Python, TypeScript/JS, Go, and PHP to verify sanitization.
---

# ViperClaw Skill 10: White-Box Source-to-Sink Taint Analysis (`viper-taint-sast`)

## Overview
Uses `viper_taint_scan` (`viperclaw taint`) to trace untrusted user inputs (`request.args`, `req.body`, `$_GET`, `r.URL.Query()`) to sensitive sinks and verify context-appropriate sanitization.

## Audit Checklist
1. **Source-to-Sink Call Chain Tracing:** Map every hop from HTTP/CLI entrypoints to SQL, command, file-path, template, and deserialization sinks.
2. **Sanitizer Verification:** Confirm that type casts (`int()`, `intval()`), prepared statements (`PDO::prepare`), path canonicalization (`realpath` + prefix check), or allowlists (`in_array`) are applied before the sink.
3. **Remediation Patch Generation:** Produce minimal, idiomatic code patches that close the unvalidated data flow without breaking application functionality.
