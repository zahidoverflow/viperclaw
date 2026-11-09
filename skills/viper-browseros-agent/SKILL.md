---
name: viper-browseros-agent
description: BrowserOS Neo & Live Signed-In Session Offensive Playbook. Bridges live BrowserOS MCP tabs (`navigate`, `snapshot`, `evaluate_in_page`, `act`, `screenshot`) with ViperClaw's `viper_browser_ingest`, `viper_jwt_attack`, `viper_race_burst`, and `viper_graphql_scan` tools to bypass TLS/WAF bot walls, harvest runtime storage/JWTs, hook `fetch`/`XHR` signers, and prove real DOM XSS execution.
---

# ViperClaw Skill 13: BrowserOS Neo & Live Session Offensive Playbook (`viper-browseros-agent`)

## 1. Why BrowserOS Neo + ViperClaw Beats Standalone Headless Scanners

Headless CLI scanners (`curl`, `httpx`, `nuclei`, or unauthenticated Docker Playwright containers) fail on modern enterprise targets because:
1. **TLS/JA3 & Anti-Bot Walls:** Cloudflare Turnstile, Akamai Bot Manager, DataDome, and Kasada block headless TLS fingerprints and empty cookie jars before the first probe reaches the origin API.
2. **Complex SSO / Passkey / MFA Sessions:** Re-implementing Okta/SAML/OAuth2/WebAuthn login flows inside a CLI script wastes hours.
3. **Client-Side Request Signing & SPA State:** Modern SPAs compute `X-Signature` / `X-Hmac` / `nonce` headers inside obfuscated Webpack chunks and store auth tokens inside `window.localStorage`, `IndexedDB`, or closure state.

By pairing **BrowserOS Neo MCP (`browseros-neo`)**—which runs inside the user's real, human-authenticated browser profile—with **ViperClaw's deterministic MCP engines (`viperclaw mcp`)**, you combine **human-grade stealth & live auth** with **automated wire exploitation**.

---

## 2. The 5-Step BrowserOS + ViperClaw Kill Chain

### Phase A: Attach to the Live BrowserOS Session & Install Runtime Hooks
1. List active tabs using `browseros-neo:tabs` (`action: "list"`) or open the target in the signed-in session.
2. Call ViperClaw's `viper_browser_ingest` tool with `action: "get_scripts"` (or run `viperclaw browser --scripts`) to retrieve the two runtime JS probes:
   - `install_runtime_hooks`: Monkey-patches `window.fetch` and `XMLHttpRequest.prototype.open` inside the live tab so every background API call, GraphQL query, and custom header is recorded in `window.__viperclaw_reqs`.
   - `extract_auth_and_state`: Dumps `document.cookie`, `window.localStorage`, `window.sessionStorage`, `<meta>` CSRF tokens, Next.js `__NEXT_DATA__`, script bundle URLs, and all captured `window.__viperclaw_reqs`.
3. Execute `install_runtime_hooks` on the target tab via `browseros-neo:evaluate_in_page`.

### Phase B: Drive UI Workflows to Trigger Lazy Chunks & Privileged API Calls
1. Use `browseros-neo:snapshot` and `browseros-neo:act` (`click`, `fill`, `press`) to navigate through multi-step workflows (settings, billing, team invites, API key creation, GraphQL views).
2. This forces Webpack/Vite/Next.js to load privileged lazy chunks and fires authenticated `fetch`/`XHR` calls through your installed hook.

### Phase C: Ingest Live Browser Telemetry into ViperClaw (`viper_browser_ingest`)
1. Run `extract_auth_and_state` via `browseros-neo:evaluate_in_page` and pass the returned JSON directly into `viper_browser_ingest` (`viperclaw browser --snapshot-json ...`).
2. `viper_browser_ingest` automatically:
   - Extracts all **JWT tokens** from `localStorage`, `sessionStorage`, and cookies, and runs `JWTEngine` (`alg:none`, HMAC secret cracking, `kid` traversal, claim audit).
   - Runs `JSHarvester` over `__NEXT_DATA__` and script manifests to reconstruct **unloaded lazy chunks**, **IDOR/BOLA endpoints**, and **SSRF parameters**.
   - Upserts every discovered route, token, and parameter into the **Stigmergic SQLite Attack Graph** (`.viperclaw/graph.db`).

### Phase D: Hand Off Authenticated State to ViperClaw's Wire Engines
Once you have the live session cookies, Bearer JWTs, or GraphQL endpoints from BrowserOS:
1. **JWT Forgery & Replay:** Call `viper_jwt_attack` with the harvested JWT and `target_url` to test `alg:none`, cracked HMAC secrets, `kid` `/dev/null`, and `RS256`→`HS256` confusion.
2. **GraphQL Introspection & Clairvoyance:** Call `viper_graphql_scan` with the harvested `/graphql` endpoint and authenticated headers.
3. **Barrier-Synchronized Race Bursts:** Call `viper_race_burst` with the authenticated `Cookie` / `Authorization` header on state-changing endpoints (coupon redemption, invite creation, credit transfer, vote/like endpoints).
4. **In-Browser Signed Replay (When Requests Are Client-Signed):** If the target signs requests inside JS (`X-Signature`), execute the BOLA/IDOR or Race `fetch()` calls *directly inside the BrowserOS tab* via `browseros-neo:evaluate_in_page` using `Promise.all([...])` so the page's own JS signer signs every probe!

### Phase E: Prove Real DOM Execution & Capture Visual + Wire Receipts
1. For Reflected/Stored/DOM XSS or Prototype Pollution, never rely on raw string reflection alone.
2. In BrowserOS, navigate to the payload URL and verify execution via `browseros-neo:evaluate_in_page` (e.g., checking a harmless DOM property or `document.domain` proof) and capture a visual receipt with `browseros-neo:screenshot`.
3. Pass the raw request/response receipt into `viper_verify_and_report` to run the **7-Question Triage Gate** and generate the final HackerOne/Bugcrowd Markdown + SARIF 2.1.0 report.
