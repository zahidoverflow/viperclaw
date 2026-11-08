---
name: viper-taint-sast
description: White-Box Multi-Language Source-to-Sink Taint Analysis & Dynamic Exploit Synthesis Skill. Uses ViperClaw's AST/structural taint tracer to locate reachable RCE, SQLi, SSRF, LFI, and Deserialization paths.
---

# ViperClaw White-Box Taint SAST (`viper-taint-sast`)

## Methodology: Follow the Data, Then Prove Reachability
Static pattern scanners drown operators in false positives because they flag every sink regardless of whether user input reaches it. ViperClaw traces **Source → Tainted Variable → Sink** and extracts compact context slices.

## Workflow

### Step 1: Run Multi-Language Taint Scan
```bash
viperclaw taint /path/to/repo --graph-db .viperclaw/graph.db
```
Or invoke the MCP tool `viper_taint_scan`.

### Step 2: Audit Each Taint Flow Slice
For every `TaintFlow` returned:
1. **Verify Route Reachability:** Check the route decorator / router registration (`@app.post`, `router.get`, `http.HandleFunc`) and required authentication middleware.
2. **Check Intermediate Sanitizers:** Inspect the `context_slice` between `source_line` and `sink_line` for type casting (`int()`), parameterized queries, or strict allowlists.
3. **Synthesize Minimal PoC:** Construct the exact HTTP request or CLI input that carries a controlled payload from `source_expr` into `sink_expr`, then verify via `viperclaw verify`.
