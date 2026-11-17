---
name: viper-browseros-agent
description: BrowserOS Neo Live Application Inspection & DOM Security Audit Skill. Uses BrowserOS MCP tabs to inspect client storage, cookie flags, CSP headers, and SPA runtime behavior.
---

# ViperClaw Skill 13: BrowserOS Neo Live Application & DOM Auditor (`viper-browseros-agent`)

## Overview
Integrates **BrowserOS Neo MCP** (`navigate`, `snapshot`, `evaluate_in_page`, `screenshot`) with `viper_browser_ingest` (`viperclaw browser`) to audit live web applications in an authenticated browser context.

## Audit Workflow
1. **Session & Storage Hygiene Inspection:** Inspect `window.localStorage`, `window.sessionStorage`, and `document.cookie` to verify that sensitive tokens are not exposed to scripts when `HttpOnly` cookies should be used.
2. **SPA Route & API Mapping:** Capture client-side API endpoints and lazy-loaded bundle references via `viper_browser_ingest` to ensure all routes are covered by server-side authorization.
3. **Client-Side Security Control Verification:** Verify DOM sanitization, Content-Security-Policy (CSP) enforcement, and UI workflow state transitions with visual screenshot documentation.
