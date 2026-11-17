---
name: viper-orchestrator
description: Master 5-Phase Security Audit & Architecture Review Orchestrator. Coordinates asset inventory, static/configuration review, OWASP verification, and evidence-backed remediation reporting.
---

# ViperClaw Skill 01: Security Audit & Architecture Review Orchestrator (`viper-orchestrator`)

## Overview
Coordinates a structured, non-destructive 5-phase security audit across source code, configurations, and application endpoints using the SQLite Assessment Graph (`.viperclaw/graph.db`).

## 5-Phase Audit Workflow
1. **Asset & Surface Inventory:** Map routes, schemas, dependencies, and authentication boundaries into the assessment graph (`viper_graph_upsert`).
2. **Static & Configuration Review:** Audit source code data flows (`viper_taint_scan`), client bundle manifests (`viper_harvest_js`), and HTTP header configurations (`viper_fingerprint_traffic`).
3. **Control Verification:** Verify access control matrices, input validation, and session handling using non-destructive baseline comparisons (`viper_diff_oracle`).
4. **Triage & CVSS Assessment:** Validate that every finding has reproducible diagnostic evidence and an accurate CVSS v3.1 score (`viper_verify_and_report`).
5. **Remediation Guidance:** Provide root-cause code fixes, parameterized patterns, and regression tests.
