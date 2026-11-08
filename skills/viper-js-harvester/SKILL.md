---
name: viper-js-harvester
description: Deep JavaScript Bundle & Webpack/Vite/Next.js Lazy-Chunk Reconstructor. Extracts hidden admin routes, API endpoints, GraphQL operations, DOM sinks, and high-entropy secrets.
---

# ViperClaw JS & Lazy-Chunk Harvester (`viper-js-harvester`)

## Why Standard Recon Fails on SPAs
Modern web apps split admin routes, internal APIs, and billing mutations into lazy-loaded chunks (`<id>.<hash>.chunk.js`) that never appear in initial HTML or passive proxy traffic unless you reconstruct the chunk manifest.

## Execution Playbook

### Step 1: Collect Initial Bundles & Runtime Manifests
Capture the live origin's main bundle, `runtime.js`, `_buildManifest.js`, or Vite index assets.

### Step 2: Reconstruct Lazy Chunks & Extract Leads
Run the ViperClaw JS Harvester against downloaded bundles:
```bash
viperclaw harvest-js ./bundles --base-url https://app.target.tld/ --graph-db .viperclaw/graph.db
```
Or invoke the MCP tool `viper_harvest_js`.

### Step 3: Triage Extracted Artifacts
1. **Unloaded Lazy Chunks (`lazy_chunks`):** Fetch every reconstructed chunk URL and re-run `viperclaw harvest-js` on the newly downloaded files.
2. **BOLA/IDOR Candidates (`idor_candidates`):** Routes containing `/users/:id`, `/orgs/{id}`, `account_id=`, `tenant_id=` -> hand off to `viper-bola-idor`.
3. **SSRF Candidates (`ssrf_candidates`):** Routes accepting `url=`, `webhook=`, `callback=`, `proxy=` -> hand off to `viper-ssrf-cloud`.
4. **Client DOM Sinks (`client_sinks`):** Inspect `postMessage` listeners lacking `event.origin` validation and `dangerouslySetInnerHTML` sinks.
