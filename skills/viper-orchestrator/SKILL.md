---
name: viper-orchestrator
description: Master 5-Phase Non-Linear Offensive Hunting Orchestrator. Combines Stigmergic Attack Graph prioritization, hypothesis decomposition, parallel subagent routing, and the 7-Question Pre-Submission Gate.
---

# ViperClaw Master Orchestrator (`viper-orchestrator`)

## Core Doctrine
Never run blind, broad scanner loops. Every engagement follows a **Hypothesis → Surface Mapping → Differential Probe → Wire-Check Proof → Report** loop backed by the ViperClaw Stigmergic Attack Graph.

## The 5-Phase Non-Linear Workflow

| Phase | Objective | ViperClaw Command / MCP Tool | Stopping Condition |
| :--- | :--- | :--- | :--- |
| **1. Surface & Stack Fingerprint** | Identify real API hosts, backend frameworks, auth cookies/headers, and WAF vendors. | `viperclaw fingerprint <capture.har>` / `viper_fingerprint_traffic` | All in-scope API origins and auth schemes mapped in graph. |
| **2. Deep JS & Lazy-Chunk Harvest** | Reconstruct unreachable Webpack/Vite/Next.js lazy chunks and extract hidden routes & sinks. | `viperclaw harvest-js <dir> --graph-db .viperclaw/graph.db` / `viper_harvest_js` | All chunk manifests parsed; IDOR/SSRF candidate routes scored. |
| **3. White-Box Taint SAST (if source available)** | Trace user-controlled sources to RCE, SQLi, SSRF, LFI, Deserialization, and SSTI sinks. | `viperclaw taint <repo> --graph-db .viperclaw/graph.db` / `viper_taint_scan` | All call-chain slices extracted and ranked by pheromone score. |
| **4. Specialist Exploitation Loop** | Route top pheromone leads (`viperclaw graph`) to specialist skills (`viper-bola-idor`, `viper-injection-oracle`, `viper-ssrf-cloud`, etc.). | `viper_graph_leads` + Parallel Subagents | Every high-pheromone lead transitions from `untested` to `verified` or `dead_end`. |
| **5. Wire-Check Proof & 7-Gate QA** | Verify raw request/response receipts, filter WAF soft-blocks, score CVSS 3.1, and emit SARIF/Markdown. | `viperclaw verify ...` / `viper_verify_and_report` | Zero unverified claims; every finding has a deterministic receipt. |

## Subagent Routing Rules
1. **Never overload a single context window:** Spawn isolated subagents per vulnerability class (`viper-bola-idor`, `viper-graphql-ws`, `viper-race-logic`).
2. **Enforce Stigmergic Coordination:** Before testing an endpoint, check `viper_graph_leads` so subagents never duplicate dead-end probes.
