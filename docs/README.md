# 📘 ViperClaw Complete Usage & Best-Utilization Guide (`v2.0.0`)

Welcome to the official **ViperClaw User Guide**. Whether you are completely new to security testing ("noob-friendly" step-by-step) or an experienced bug bounty hunter looking to automate your workflow inside **Google Antigravity**, **Claude Code**, **OpenAI Codex**, or **Cursor**, this guide explains **what every feature does, when to use it, and how to combine them for maximum results**.

---

## 📑 Table of Contents

1. [What Is ViperClaw? (In Plain English)](#-1-what-is-viperclaw-in-plain-english)
2. [🚀 Quickstart (Step-by-Step Setup)](#-2-quickstart-step-by-step-setup)
3. [Mode 1: Using the Standalone CLI (Command-by-Command)](#-3-mode-1-using-the-standalone-cli-command-by-command)
   - [`viperclaw scan` — Live Web App & Lab Scanner](#31-viperclaw-scan--live-web-app--lab-scanner-dast)
   - [`viperclaw taint` — Source Code Vulnerability Scanner (SAST)](#32-viperclaw-taint--source-code-vulnerability-scanner-sast)
   - [`viperclaw harvest-js` — JavaScript Bundle & Hidden Chunk Analyzer](#33-viperclaw-harvest-js--javascript-bundle--hidden-chunk-analyzer)
   - [`viperclaw fingerprint` — Caido / Burp HAR Traffic Analyzer](#34-viperclaw-fingerprint--caido--burp-har-traffic-analyzer)
   - [`viperclaw graph` — Stigmergic Attack Surface Knowledge Graph](#35-viperclaw-graph--stigmergic-attack-surface-knowledge-graph)
   - [`viperclaw verify` — 7-Gate Proof Judge, CVSS 3.1 & Report Generator](#36-viperclaw-verify--7-gate-proof-judge-cvss-31--report-generator)
4. [Mode 2: Using ViperClaw Inside Your AI Coding Agent (Best Prompts)](#-4-mode-2-using-viperclaw-inside-your-ai-coding-agent-best-prompts)
5. [4 Best-Utilization Playbooks (Real-World Workflows)](#-5-4-best-utilization-playbooks-real-world-workflows)
6. [How the 7-Question Gate Prevents False Positives](#-6-how-the-7-question-gate-prevents-false-positives)
7. [Pro Tips, Troubleshooting & Security Guardrails](#-7-pro-tips-troubleshooting--security-guardrails)

---

## 🧠 1. What Is ViperClaw? (In Plain English)

When people try to use AI for penetration testing or bug bounty hunting, they usually run into two problems:
1. **The AI guesses or hallucinates bugs** that aren't actually exploitable (for example, mistaking a Cloudflare `"200 OK"` block page for a real vulnerability).
2. **The AI doesn't have a structured hunting plan**, so it runs random commands and misses deep bugs like hidden JavaScript admin routes, multi-hop code vulnerabilities, or cross-account data leaks (IDOR/BOLA).

**ViperClaw fixes both problems** by giving you **three connected tools** in a single, zero-dependency Python package:

| Component | What It Is | How You Use It |
| :--- | :--- | :--- |
| **1. The CLI (`viperclaw` / `vclaw`)** | A fast command-line tool you can run in any terminal. | Run `viperclaw scan`, `viperclaw taint`, `viperclaw harvest-js`, `viperclaw fingerprint`, `viperclaw graph`, or `viperclaw verify`. |
| **2. The 14 Offensive Skills (`skills/`)** | 12 step-by-step hunting playbooks (`SKILL.md`) written for AI coding agents. | Installed once with `viperclaw skills install --target all`. Your AI agent automatically reads them when you ask it to hunt bugs. |
| **3. The MCP Server (`viperclaw mcp`)** | A bridge that lets your AI agent run ViperClaw's analyzers directly as native tools. | Added once to your agent's `mcp_config.json`. Gives your AI 8 deterministic security tools (`viper_live_scan`, `viper_taint_scan`, etc.). |

---

## 🚀 2. Quickstart (Step-by-Step Setup)

### Step 1: Install the ViperClaw Python Package
ViperClaw uses **100% pure Python 3.10+ standard library modules** (zero external dependencies to break).

```bash
git clone https://github.com/zahidoverflow/viperclaw.git
cd viperclaw
pip install -e .
```

Verify that it works by running:
```bash
viperclaw --version
# Output: viperclaw 1.2.0
```
*(Tip: You can type either `viperclaw` or the shorter alias `vclaw` for any command!)*

### Step 2: Install the 14 Offensive Skills into Your AI Agent
Tell ViperClaw to copy its 12 hunting playbooks into your AI coding assistant's skill folder:

```bash
# Install for ALL supported agents at once (Antigravity, Claude Code, Codex, Cursor):
viperclaw skills install --target all
```

Or install for a specific agent only:
* **Google Antigravity:** `viperclaw skills install --target antigravity` (installs to `~/.agents/skills/`)
* **Claude Code:** `viperclaw skills install --target claude` (installs to `~/.claude/skills/`)
* **OpenAI Codex:** `viperclaw skills install --target codex` (installs to `~/.codex/skills/`)
* **Cursor:** `viperclaw skills install --target cursor` (installs to `~/.cursor/skills/`)

### Step 3: Connect the MCP Server to Your AI Agent
To let your AI agent execute ViperClaw tools automatically, add this block to your agent's MCP configuration file (`mcp_config.json` or `.mcp.json`):

```json
{
  "mcpServers": {
    "viperclaw": {
      "command": "viperclaw",
      "args": ["mcp"]
    }
  }
}
```
*(If you use Claude Code CLI, you can simply run: `claude mcp add viperclaw -- viperclaw mcp`)*

---

## 💻 3. Mode 1: Using the Standalone CLI (Command-by-Command)

You don't even need an AI agent open to use ViperClaw—every analyzer works directly from your terminal. Here is how each command works in detail.

---

### 3.1 `viperclaw scan` — Live Web App & Lab Scanner (DAST)

**What it does:** Connects to a live web application or training lab (like DVWA or a local staging server), automatically logs in, tracks session cookies and anti-CSRF tokens, crawls pages, tests for 14 classes of web vulnerabilities over the wire, saves leads into the Attack Graph, and generates verified reports.

```bash
viperclaw scan http://127.0.0.1:4280 \
  --db .viperclaw/graph.db \
  --report-md bounty_report.md \
  --report-sarif findings.sarif
```

**Optional Login Flags:**
* `--username <user>` (default: `admin`)
* `--password <pass>` (default: `password`)
* `--security-level <low|medium|high>` (default: `low` for DVWA labs)
* `--timeout <seconds>` (default: `10.0`)

**What you get back:**
1. JSON summary printed to your terminal listing every verified vulnerability (`VC-LIVE-001`, etc.) with raw HTTP request/response proof receipts and CVSS v3.1 scores.
2. `bounty_report.md`: A complete HackerOne/Bugcrowd-formatted Markdown report ready for review.
3. `findings.sarif`: A SARIF 2.1.0 file you can upload to GitHub Code Scanning or open in VS Code.

---

### 3.2 `viperclaw taint` — Source Code Vulnerability Scanner (SAST)

**What it does:** Scans source code folders or individual files across **Python (`.py`), TypeScript/JavaScript (`.ts`, `.tsx`, `.js`, `.jsx`, `.mjs`), Go (`.go`), and PHP (`.php`)**.

Unlike basic `grep` or regex scanners that flag every SQL query even when it's safe, `viperclaw taint`:
1. Finds where **untrusted user input** enters the code (e.g., `request.args.get("id")`, `req.body`, `r.URL.Query()`, `$_GET['ip']`).
2. Tracks that variable **step-by-step across variable re-assignments and string formatting** (multi-hop taint tracking).
3. Checks if the variable was **sanitized or guarded** along the way (e.g., `int()`, `intval()`, `is_numeric()`, `PDO::prepare()`, `htmlspecialchars()`, `in_array()` allowlists). If sanitized, it **de-taints** the variable so you get zero false positives!
4. Alerts you only when **unsanitized** user input reaches a dangerous sink (**Command Injection / RCE, SQL Injection, SSRF, LFI / Path Traversal, Insecure Deserialization, XSS, or SSTI**).

```bash
viperclaw taint ./path/to/source-code \
  --db .viperclaw/graph.db \
  --output taint_flows.json
```

**How to read the output (`taint_flows.json`):**
* `vuln_class`: The bug type (e.g., `"SQL Injection (SQLi)"` or `"Remote Code Execution (RCE)"`).
* `file` & `sink_line`: Exact file path and line number where the bug triggers (`file.py:42`).
* `source_var` & `tainted_vars`: The chain of variables that carried the attacker's input from the HTTP request to the dangerous function.
* `remediation`: How to fix the code safely.

---

### 3.3 `viperclaw harvest-js` — JavaScript Bundle & Hidden Chunk Analyzer

**What it does:** Modern Single-Page Applications (React, Next.js, Vue, Vite, Webpack) hide admin panels and internal API calls inside **lazy-loaded JavaScript chunk files** that never load in your browser unless you have admin permissions.

`viperclaw harvest-js` reads downloaded `.js` bundles and:
1. **Reconstructs hidden lazy-chunk URLs** (e.g., `https://app.target.tld/admin-panel.a1b2c3d4.chunk.js` or `/_next/static/chunks/...`) so you can fetch and inspect code that regular users never see.
2. **Extracts API endpoints** (`/api/v2/orgs/...`, `/internal/webhooks/...`).
3. **Flags IDOR/BOLA & SSRF parameter candidates** (endpoints containing `user_id`, `org_id`, `account_id`, `url`, `webhook`, `callback`, etc.).
4. **Extracts GraphQL queries/mutations**, **DOM XSS sinks** (`innerHTML`, `dangerouslySetInnerHTML`), and **leaked API keys/secrets**.

```bash
viperclaw harvest-js ./downloaded_js_folder \
  --base-url https://app.target.tld/ \
  --db .viperclaw/graph.db \
  --output js_recon.json
```

---

### 3.4 `viperclaw fingerprint` — Caido / Burp HAR Traffic Analyzer

**What it does:** When you browse a target web app through an intercepting proxy (**Caido** or **Burp Suite**), you can export your HTTP history as a `.har` file. `viperclaw fingerprint` analyzes that `.har` file to:
1. Discover **sibling API subdomains** (`api.target.tld`, `internal-gw.target.tld`) related to your target domain.
2. Fingerprint the **exact backend framework** (**FastAPI, Django, Flask, NestJS, Express, Spring Boot, Laravel, Ruby on Rails, ASP.NET, GraphQL**) based on error JSON shapes, headers, and cookie names.
3. Detect **WAF & anti-bot vendors** (Cloudflare, Akamai, Imperva, CloudFront, DataDome) so you know what protections are active.

```bash
viperclaw fingerprint ./proxy_traffic.har \
  --domain target.tld \
  --output tech_stack.json
```

---

### 3.5 `viperclaw graph` — Stigmergic Attack Surface Knowledge Graph

**What it does:** Every time you run `scan`, `taint`, or `harvest-js` with `--db .viperclaw/graph.db`, ViperClaw stores all discovered endpoints, lazy chunks, taint sinks, and findings inside a local SQLite database and ranks them using **pheromone priority scores** (high-risk leads automatically bubble to the top).

```bash
# View the top 10 highest-priority attack leads:
viperclaw graph --db .viperclaw/graph.db --top-leads 10

# Apply pheromone decay (0.9x) so older low-signal leads fade out:
viperclaw graph --db .viperclaw/graph.db --top-leads 10 --decay 0.9

# Export the entire attack graph as a Mermaid flowchart diagram:
viperclaw graph --db .viperclaw/graph.db --mermaid
```

---

### 3.6 `viperclaw verify` — 7-Gate Proof Judge, CVSS 3.1 & Report Generator

**What it does:** Before you submit a bug bounty report to HackerOne, Bugcrowd, or Intigriti, `viperclaw verify` acts as a strict **Quality Assurance Judge**. It checks whether your finding passes all **7 Pre-Submission Gates** (including checking that your HTTP response isn't a Cloudflare/Akamai Soft-200 block page), calculates the exact **CVSS v3.1 score & vector string**, and generates a polished **Markdown report** and **SARIF 2.1.0** file.

#### Option A: Verify Using a JSON File (Recommended for beginners)
Create a file called `my_finding.json`:
```json
{
  "finding_id": "VC-2026-001",
  "title": "Cross-Tenant BOLA on /api/v2/orgs/{id}/invoices Exposes Other Customers' Billing PII",
  "vuln_class": "Broken Object Level Authorization (BOLA / IDOR)",
  "endpoint": "GET /api/v2/orgs/1001/invoices",
  "cvss_metrics": {
    "AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"
  },
  "gate_answers": {
    "q1_in_scope": true,
    "q2_not_waf_soft_block": true,
    "q3_real_security_boundary_crossed": true,
    "q4_reproducible_wire_receipt": true,
    "q5_not_self_only_or_intended": true,
    "q6_concrete_business_impact": true,
    "q7_accurate_cvss_and_remediation": true
  },
  "reproduction_steps": [
    "Authenticate as Tenant B (org_id=2002) and capture the Bearer token.",
    "Send GET /api/v2/orgs/1001/invoices with Tenant B's Bearer token.",
    "Observe HTTP 200 OK returning Tenant A's private billing records and tax ID."
  ],
  "request_receipt": "GET /api/v2/orgs/1001/invoices HTTP/1.1\nHost: api.target.tld\nAuthorization: Bearer eyJ...",
  "response_receipt": "HTTP/1.1 200 OK\nContent-Type: application/json\n\n{\"org_id\": 1001, \"tax_id\": \"XX-998877\", \"total_usd\": 48500}",
  "impact": "Any authenticated user can enumerate organization IDs and download sensitive billing invoices and tax identifiers belonging to other tenants.",
  "remediation": "Enforce organization ownership checks in the invoice controller by verifying that current_user.org_id matches the requested org_id parameter."
}
```

Then run:
```bash
viperclaw verify ./my_finding.json \
  --report-md h1_submission.md \
  --report-sarif findings.sarif
```

#### Option B: Verify Inline Directly from CLI Flags
```bash
viperclaw verify \
  --id "VC-2026-001" \
  --title "Cross-Tenant BOLA on /api/v2/orgs/{id}/invoices" \
  --vuln-class "BOLA / IDOR" \
  --endpoint "GET /api/v2/orgs/1001/invoices" \
  --request-receipt "GET /api/v2/orgs/1001/invoices HTTP/1.1" \
  --response-receipt 'HTTP/1.1 200 OK\n{"org_id":1001,"tax_id":"XX-998877"}' \
  --impact "Cross-tenant PII and invoice disclosure." \
  --remediation "Validate current_user.org_id == params.org_id before returning invoice records." \
  --report-md h1_submission.md
```

---

## 🤖 4. Mode 2: Using ViperClaw Inside Your AI Coding Agent (Best Prompts)

Once you have installed the 12 Skills (`viperclaw skills install --target all`) and connected the MCP Server (`viperclaw mcp`), you can talk to **Google Antigravity**, **Claude Code**, **Codex**, or **Cursor** in plain English.

Here are the **5 best copy-paste prompts** to get senior-level results:

### Prompt 1: Auditing a Code Repository (White-Box SAST)
> *"Use the `viper-taint-sast` and `viper-proof-judge` skills. Run `viper_taint_scan` on `./src`, trace every unsanitized user input to its sink, check if any sanitizer blocks it, and generate verified PoCs and a HackerOne Markdown report for confirmed vulnerabilities."*

### Prompt 2: Hunting a Live Lab or Web App (Black-Box DAST)
> *"Use `viper-orchestrator`. Run `viper_live_scan` against `http://127.0.0.1:4280`, update the Stigmergic Attack Graph, verify all exploitable vulnerabilities through `viper_verify_and_report`, and save the final report to `bounty_report.md`."*

### Prompt 3: Uncovering Hidden Admin Routes in Frontend JS
> *"Use `viper-js-harvester`. Run `viper_harvest_js` on `./bundles` with base URL `https://app.target.tld/`, reconstruct all unloaded Webpack/Vite/Next.js lazy chunk URLs, download the new chunks, and list the top IDOR and SSRF parameter leads from the Attack Graph."*

### Prompt 4: Testing Cross-Account BOLA / IDOR with Two Sessions
> *"Use `viper-bola-idor`. Compare User A's baseline response vs. User B's cross-tenant response on `/api/v2/orgs/1001/invoices` using `viper_diff_oracle`. Confirm it isn't a WAF Soft-200 block or error envelope, and if confirmed, generate a CVSS 3.1 report."*

### Prompt 5: Full 5-Phase Bug Bounty Session from Proxy Traffic
> *"Use `viper-orchestrator` and `viper-proxy-fingerprint`. Analyze `./caido_export.har` for `target.tld` using `viper_fingerprint_traffic`, populate the Attack Graph, query the top 10 pheromone leads with `viper_graph_leads`, and test the highest-priority endpoints."*

---

## 🏆 5. 4 Best-Utilization Playbooks (Real-World Workflows)

To get the most out of ViperClaw, combine its tools in these proven workflows:

### Playbook A: The "JS + HAR → BOLA/IDOR" Web App Workflow
1. **Capture Traffic:** Browse the target app normally as User A while running Caido or Burp Suite, and export `traffic.har` + save the main JS bundles into `./bundles/`.
2. **Fingerprint Stack:** Run `viperclaw fingerprint ./traffic.har --domain target.tld` to find sibling API hosts and the backend framework.
3. **Harvest Hidden Chunks:** Run `viperclaw harvest-js ./bundles --base-url https://app.target.tld/ --db .viperclaw/graph.db` to uncover hidden admin routes and IDOR parameters (`org_id`, `invoice_id`).
4. **Rank Leads:** Run `viperclaw graph --db .viperclaw/graph.db --top-leads 10` to see which endpoints have the highest pheromone score.
5. **Prove with Diff Oracle:** Replay the top endpoints with User B's token, verify the leak with `viper_diff_oracle` / `viperclaw verify`, and export `h1_submission.md`.

### Playbook B: The "Zero-Noise White-Box Repo Audit" Workflow
1. **Run Polyglot Taint SAST:** Run `viperclaw taint ./repo --db .viperclaw/graph.db --output taint_flows.json`.
2. **Review Unsanitized Flows:** Because ViperClaw automatically filters out routes protected by `int()`, `intval()`, `PDO::prepare`, `htmlspecialchars`, and `in_array` allowlists, every remaining flow in `taint_flows.json` has a direct unsanitized path from remote input to a dangerous sink.
3. **Verify & Export SARIF:** Confirm reachability and run `viperclaw verify` with `--report-sarif findings.sarif`.

### Playbook C: The "CI/CD Pre-Merge Security Gate" Workflow
Add ViperClaw to your GitHub Actions or GitLab CI pipeline in 2 lines—zero Docker containers or external API keys required:
```yaml
- name: Run ViperClaw Polyglot Taint SAST
  run: |
    pip install .
    viperclaw taint ./src --output taint_results.json
```

---

## 🛡️ 6. How the 7-Question Gate Prevents False Positives

Every finding verified by `ProofOracle` ([`src/viperclaw/core/oracle.py`](../src/viperclaw/core/oracle.py)) must pass **all 7 pre-submission gates** before ViperClaw marks it `VERIFIED`:

1. **`q1_in_scope`:** Is the target host/endpoint explicitly in scope?
2. **`q2_not_waf_soft_block`:** Is the HTTP response a genuine application response and **not** a Cloudflare, Akamai, Imperva, CloudFront, PerimeterX, or DataDome `"200 OK"` challenge/block page?
3. **`q3_real_security_boundary_crossed`:** Did the test cross a real privilege or tenant boundary (e.g., User B reading User A's private data, or unauthenticated RCE/LFI)?
4. **`q4_reproducible_wire_receipt`:** Are non-empty, raw HTTP request and response receipts attached (`No Receipt, No Report`)?
5. **`q5_not_self_only_or_intended`:** Is the behavior NOT a self-XSS, missing non-security header, or intended public feature?
6. **`q6_concrete_business_impact`:** Can you state the exact confidentiality, integrity, or availability impact without guessing (*never write "could potentially"*)?
7. **`q7_accurate_cvss_and_remediation`:** Are the CVSS v3.1 metrics and root-cause remediation accurate?

---

## 💡 7. Pro Tips, Troubleshooting & Security Guardrails

* **Keep Scan Artifacts Out of Git:** ViperClaw's [`.gitignore`](../.gitignore) automatically ignores `.viperclaw/`, `*.db`, `*.sarif`, `*.har`, `*report*.md`, and `*.json` scan outputs so you never accidentally commit live target data or session cookies.
* **Never Commit `.har` or `.env` Files:** `.har` exports from Caido or Burp Suite contain live `Authorization` headers and session cookies. Store them in an ignored folder like `recon/` or outside the git repository.
* **Authorized Targets Only:** Only run `viperclaw scan` and active probes against targets where you have explicit written permission (bug bounty programs in scope, your own applications, or authorized labs like DVWA / HackTheBox / TryHackMe).
