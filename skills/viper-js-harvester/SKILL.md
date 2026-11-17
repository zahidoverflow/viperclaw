---
name: viper-js-harvester
description: Client-Side Bundle & SPA Manifest Auditor. Reviews Webpack, Vite, and Next.js build artifacts to inventory client routes, API references, DOM sinks, and accidentally bundled secrets.
---

# ViperClaw Skill 02: Client-Side Bundle & SPA Manifest Auditor (`viper-js-harvester`)

## Overview
Audits JavaScript/TypeScript build artifacts (`viper_harvest_js`) to identify exposed development routes, client-side secrets, and unsafe DOM manipulation sinks.

## Audit Checklist
1. **Route & Chunk Inventory:** Inspect Webpack/Vite/Next.js build manifests to ensure administrative or internal modules are not exposed in public client bundles.
2. **Hardcoded Secret Detection:** Scan client bundles for accidentally embedded API keys, private tokens, or internal staging URLs that belong in server-side environment variables.
3. **DOM Sink Review:** Locate uses of `innerHTML`, `dangerouslySetInnerHTML`, `document.write`, and unvalidated `postMessage` listeners, and recommend safe text-binding or DOMPurify sanitization.
