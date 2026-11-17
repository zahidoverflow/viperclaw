---
name: viper-remediation-patch-verifier
description: Security Patch Synthesizer & Regression Test Generator. Produces minimal root-cause code fixes for CWE findings and writes automated pytest/jest unit tests to verify the fix.
---

# ViperClaw Skill 34: Security Remediation & Regression Test Verifier (`viper-remediation-patch-verifier`)

## Overview
Guides the engineering workflow from a verified security audit finding to a minimal, production-ready code patch backed by automated unit/integration regression tests.

## Remediation Workflow
1. **Fix the Root Cause, Not the Symptom:** Replace string-concatenated queries with parameterized statements, add explicit tenant/ownership predicates to ORM queries, or enforce schema validation at the controller boundary rather than adding fragile regex blacklists.
2. **Preserve Backward Compatibility:** Ensure legitimate API callers, types, and status codes continue to work as expected.
3. **Write Dual Regression Tests:**
   - **Positive Test:** Confirms authorized, valid inputs still succeed.
   - **Negative Security Test:** Confirms unauthorized cross-tenant access, invalid tokens, or unparameterized special characters are deterministically rejected, then re-run `viperclaw taint` / `pytest` to verify `0` remaining flows.
