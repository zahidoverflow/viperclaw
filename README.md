<div align="center">

<img src="assets/banner.svg" alt="ViperClaw — AI Pentesting Framework, Bug Bounty Automation MCP Server, Multi-Language SAST Taint Analyzer, and 12 Offensive Security Skills for Google Antigravity, Claude Code, OpenAI Codex, and Cursor" width="100%" />

<p align="center">
  <a href="https://github.com/zahidoverflow/viperclaw/releases"><img src="https://img.shields.io/github/v/release/zahidoverflow/viperclaw?style=flat-square&logo=github&color=10b981&label=Release" alt="Latest GitHub Release" /></a>
  <a href="https://github.com/zahidoverflow/viperclaw/actions"><img src="https://img.shields.io/github/actions/workflow/status/zahidoverflow/viperclaw/ci.yml?branch=main&style=flat-square&logo=githubactions&logoColor=white&label=CI" alt="GitHub Actions CI Status" /></a>
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/Python-3.10%2B%20%7C%20Zero%20Deps-06b6d4?style=flat-square&logo=python&logoColor=white" alt="Python 3.10+ Zero Dependencies" /></a>
  <a href="#-cli--mcp-reference"><img src="https://img.shields.io/badge/MCP-8%20Tools-a855f7?style=flat-square" alt="Model Context Protocol MCP Server" /></a>
  <a href="#-offensive-skill-playbooks"><img src="https://img.shields.io/badge/Skills-12%20Playbooks-f43f5e?style=flat-square" alt="12 Bug Bounty & Pentesting Skills" /></a>
  <a href="https://github.com/zahidoverflow/viperclaw/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-10b981?style=flat-square" alt="MIT License" /></a>
</p>

<p align="center">
  <b>ViperClaw</b> (<code>viperclaw</code> / <code>vclaw</code>) upgrades <b>Google Antigravity</b>, <b>Claude Code</b>, <b>OpenAI Codex</b>, and <b>Cursor</b> into a methodology-driven offensive security &amp; bug bounty platform—combining <b>12 offensive skills</b>, an <b>8-tool Phase-Gated MCP server</b>, a <b>Stigmergic SQLite Attack Graph</b>, <b>multi-language SAST/DAST analyzers</b>, and a <b>deterministic Proof Oracle</b> with <b>zero third-party runtime dependencies</b>.
</p>

<p align="center">
  <a href="https://zahidoverflow.github.io/viperclaw/"><b>Website</b></a> •
  <a href="docs/README.md"><b>User Guide</b></a> •
  <a href="#-quickstart"><b>Quickstart</b></a> •
  <a href="#-architecture"><b>Architecture</b></a> •
  <a href="#-cli--mcp-reference"><b>CLI &amp; MCP</b></a> •
  <a href="#-offensive-skill-playbooks"><b>12 Skills</b></a> •
  <a href="#-benchmarks--comparison"><b>Benchmarks</b></a>
</p>

</div>

---

## ⚡ Why ViperClaw?

Most "AI pentesting wrappers" fail in production: dumping **150+ noisy CLI scanners** into an LLM causes context-window rot and instant WAF blocks, while monolithic Docker stacks require **4–6 containers and separate API budgets** when you already run a frontier coding agent locally.

ViperClaw pairs **12 methodology-driven playbooks** with a **zero-dependency Python 3.10+ engine** and a strict **"No Receipt, No Report" Proof Oracle**:

| Core&nbsp;Subsystem | Capability &amp; Implementation |
| :--- | :--- |
| 🕸️&nbsp;[**Stigmergic&nbsp;Graph**](src/viperclaw/core/graph.py) | Zero-setup SQLite knowledge graph with pheromone priority scoring, decay &amp; Mermaid topology export. |
| 🌐&nbsp;[**Live&nbsp;Wire&nbsp;Scanner**](src/viperclaw/analyzers/live_scanner.py) | Stateful cookie/CSRF session handling and **14 wire-verified HTTP exploit probes** (RCE, SQLi, LFI, XSS, Logic). |
| 🔬&nbsp;[**Polyglot&nbsp;Taint&nbsp;SAST**](src/viperclaw/analyzers/taint.py) | Multi-hop source-to-sink taint tracking across **Python, TS/JS, Go &amp; PHP** with sanitizer awareness. |
| 🧩&nbsp;[**JS&nbsp;Chunk&nbsp;Harvester**](src/viperclaw/analyzers/js_harvester.py) | Reconstructs unloaded **Webpack, Vite &amp; Next.js** lazy chunks, hidden admin routes, IDOR params &amp; secrets. |
| 🕵️&nbsp;[**HAR&nbsp;Fingerprinter**](src/viperclaw/analyzers/proxy_fingerprint.py) | Infers backend stacks (**FastAPI, NestJS, Spring, Laravel, Rails**) &amp; sibling APIs from Caido / Burp `.har` captures. |
| 🛡️&nbsp;[**7&#8209;Gate&nbsp;Proof&nbsp;Oracle**](src/viperclaw/core/oracle.py) | Rejects Cloudflare/Akamai/Imperva **Soft-200** traps, diffs BOLA JSON keys, scores **CVSS 3.1** &amp; exports **SARIF 2.1.0**. |

---

## 🚀 Quickstart

> 📘 **New to ViperClaw?** Read the complete step-by-step [**Beginner-to-Pro User Guide (`docs/README.md`)**](docs/README.md).

```bash
# 1. Clone & install (<2 seconds, zero external dependencies, Python 3.10+)
git clone https://github.com/zahidoverflow/viperclaw.git
cd viperclaw
pip install -e .

# 2. Install all 12 offensive skills into Antigravity, Claude Code, Codex & Cursor
viperclaw skills install --target all
```

<details>
<summary><b>🔌 Connect the Phase-Gated MCP Server (<code>mcp_config.json</code> / Claude Code / Cursor)</b></summary>
<br />

Add `viperclaw mcp` to your agent's `mcp_config.json` / `.mcp.json` (or run `claude mcp add viperclaw -- viperclaw mcp`):

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

* **Single-Harness Skill Install:** Use `--target antigravity`, `--target claude`, `--target codex`, or `--target cursor`.
* **Claude Code Plugin Marketplace:** Run `/plugin marketplace add zahidoverflow/viperclaw` then `/plugin install viperclaw@viperclaw`.

</details>

---

## 🧬 Architecture

<div align="center">
  <img src="assets/architecture.svg" alt="ViperClaw 4-Layer Offensive Architecture — AI Coding Harnesses, 12 Methodology Skills, 8-Tool Phase-Gated MCP Server, Pure-Python Offensive Analyzers, and 7-Gate Proof Oracle" width="100%" />
</div>

---

## 💻 CLI & MCP Reference

Both `viperclaw` and the shorthand `vclaw` alias provide standalone CLI subcommands as well as the JSON-RPC 2.0 `stdio` MCP bridge:

| CLI&nbsp;Command | Purpose &amp; Key Flags |
| :--- | :--- |
| <code>viperclaw&nbsp;scan&nbsp;&lt;url&gt;</code> | Stateful live HTTP web scanner &amp; wire-verified exploit runner (`--db`, `--report-md`, `--report-sarif`). |
| <code>viperclaw&nbsp;taint&nbsp;&lt;path&gt;</code> | Multi-language source-to-sink taint SAST for Python, TS/JS, Go &amp; PHP (`--db`, `--output`). |
| <code>viperclaw&nbsp;harvest&#8209;js&nbsp;&lt;path&gt;</code> | Webpack / Vite / Next.js lazy-chunk, hidden endpoint &amp; secret harvester (`--base-url`, `--db`, `--output`). |
| <code>viperclaw&nbsp;fingerprint&nbsp;&lt;har&gt;</code> | Caido / Burp `.har` backend framework &amp; sibling API fingerprinter (`--domain`, `--output`). |
| <code>viperclaw&nbsp;graph</code> | Query top pheromone-ranked attack leads &amp; export Mermaid topology (`--db`, `--top-leads`, `--mermaid`). |
| <code>viperclaw&nbsp;verify&nbsp;[file]</code> | Run the 7-Question Triage Gate, CVSS 3.1 calculator &amp; H1 MD / SARIF exporter (`--report-md`, `--report-sarif`). |

<details>
<summary><b>📋 View Copy-Paste CLI Workflow Examples (Live DAST, Taint SAST, JS Recon, HAR)</b></summary>
<br />

```bash
# 1. Run a stateful live web scan & export verified HackerOne Markdown + SARIF 2.1.0
viperclaw scan http://127.0.0.1:4280 --db .viperclaw/graph.db --report-md bounty_report.md --report-sarif findings.sarif

# 2. Audit source code for multi-hop taint flows (Python / TS / JS / Go / PHP)
viperclaw taint ./target-repo --db .viperclaw/graph.db --output taint_flows.json

# 3. Reconstruct hidden SPA lazy chunks & extract API / IDOR / SSRF parameters
viperclaw harvest-js ./bundles --base-url https://app.target.tld/ --db .viperclaw/graph.db --output js_recon.json

# 4. Fingerprint backend stacks from Caido / Burp HAR traffic & view top attack leads
viperclaw fingerprint ./traffic.har --domain target.tld --output tech_stack.json
viperclaw graph --db .viperclaw/graph.db --top-leads 10 --mermaid
```

</details>

<details>
<summary><b>🔌 View All 8 Phase-Gated MCP Server Tools (<code>viperclaw mcp</code>)</b></summary>
<br />

| MCP&nbsp;Tool | Phase | Description |
| :--- | :--- | :--- |
| `viper_live_scan` | **DAST** | Execute a stateful, authenticated HTTP dynamic scan against a live web target, proving exploits over the wire. |
| `viper_taint_scan` | **SAST** | Run multi-language source-to-sink taint analysis across Python, TypeScript/JavaScript, Go, and PHP. |
| `viper_harvest_js` | **Recon** | Reconstruct Webpack/Vite/Next.js lazy chunks and extract endpoints, IDOR/SSRF candidates, GraphQL ops &amp; secrets. |
| `viper_fingerprint_traffic` | **Recon** | Fingerprint backend frameworks, WAFs, sibling API hosts, and error envelopes from `.har` captures or HTTP headers. |
| `viper_graph_upsert` | **Graph** | Upsert hosts, endpoints, lazy chunks, taint sinks, or findings into the Stigmergic SQLite Attack Graph. |
| `viper_graph_leads` | **Graph** | Query top pheromone-ranked attack leads and export a live Mermaid topology diagram. |
| `viper_diff_oracle` | **Verify** | Compare baseline vs. mutated/cross-tenant HTTP responses to confirm BOLA/IDOR and filter WAF Soft-200 blocks. |
| `viper_verify_and_report` | **Report** | Run the 7-Question Triage Gate, calculate exact CVSS v3.1 scores, and generate HackerOne/Bugcrowd Markdown. |

</details>

---

## 🎯 Offensive Skill Playbooks

Each skill in [`skills/`](skills/) encodes a senior security researcher's hypothesis tree, bypass ladder, and stopping conditions across 4 operational domains:

* **🧭 Orchestration & QA (`01`, `12`):** <a href="skills/viper-orchestrator/SKILL.md"><code>viper-orchestrator</code></a> (5-Phase Swarm Graph router) and <a href="skills/viper-proof-judge/SKILL.md"><code>viper-proof-judge</code></a> (7-Gate Proof Oracle & CVSS 3.1 judge).
* **🔭 Recon & White-Box SAST (`02`, `03`, `10`):** <a href="skills/viper-js-harvester/SKILL.md"><code>viper-js-harvester</code></a> (SPA lazy chunks), <a href="skills/viper-proxy-fingerprint/SKILL.md"><code>viper-proxy-fingerprint</code></a> (HAR stack profiling), and <a href="skills/viper-taint-sast/SKILL.md"><code>viper-taint-sast</code></a> (Polyglot taint auditing).
* **⚔️ Web, API & Cloud Exploitation (`04`–`09`):** <a href="skills/viper-bola-idor/SKILL.md"><code>viper-bola-idor</code></a>, <a href="skills/viper-injection-oracle/SKILL.md"><code>viper-injection-oracle</code></a>, <a href="skills/viper-ssrf-cloud/SKILL.md"><code>viper-ssrf-cloud</code></a>, <a href="skills/viper-auth-oauth-jwt/SKILL.md"><code>viper-auth-oauth-jwt</code></a>, <a href="skills/viper-graphql-ws/SKILL.md"><code>viper-graphql-ws</code></a>, and <a href="skills/viper-race-logic/SKILL.md"><code>viper-race-logic</code></a>.
* **🤖 AI & Agentic Red-Teaming (`11`):** <a href="skills/viper-ai-llm-redteam/SKILL.md"><code>viper-ai-llm-redteam</code></a> (Prompt injection, MCP tool hijacking & RAG exfiltration).

<details>
<summary><b>📚 View Full 12-Skill Directory &amp; Methodology Breakdown</b></summary>
<br />

| # | Skill&nbsp;Playbook | Offensive Focus &amp; Methodology |
| :---: | :--- | :--- |
| `01` | <a href="skills/viper-orchestrator/SKILL.md"><code>viper&#8209;orchestrator</code></a> | **5-Phase Orchestrator:** Attack Graph prioritization, hypothesis decomposition &amp; subagent routing. |
| `02` | <a href="skills/viper-js-harvester/SKILL.md"><code>viper&#8209;js&#8209;harvester</code></a> | **JS &amp; Lazy-Chunk Harvester:** Unloaded Webpack/Vite/Next.js chunks, hidden admin routes &amp; secrets. |
| `03` | <a href="skills/viper-proxy-fingerprint/SKILL.md"><code>viper&#8209;proxy&#8209;fingerprint</code></a> | **HTTP &amp; Proxy Fingerprinter:** Sibling API discovery, framework error envelopes &amp; WAF soft-block detection. |
| `04` | <a href="skills/viper-bola-idor/SKILL.md"><code>viper&#8209;bola&#8209;idor</code></a> | **Cross-Tenant BOLA / IDOR:** Multi-role auth matrix (`Tenant A` vs. `Tenant B`), ID mutation &amp; JSON diffing. |
| `05` | <a href="skills/viper-injection-oracle/SKILL.md"><code>viper&#8209;injection&#8209;oracle</code></a> | **Precision Injection Oracle:** Zero-noise boolean/time differential pairs for SQLi, NoSQLi, SSTI &amp; CMDi. |
| `06` | <a href="skills/viper-ssrf-cloud/SKILL.md"><code>viper&#8209;ssrf&#8209;cloud</code></a> | **SSRF &amp; Cloud Metadata:** URL parser differentials, redirect chains, AWS/GCP/Azure IMDS &amp; K8s discovery. |
| `07` | <a href="skills/viper-auth-oauth-jwt/SKILL.md"><code>viper&#8209;auth&#8209;oauth&#8209;jwt</code></a> | **Auth, OAuth 2.0 &amp; JWT:** `redirect_uri` bypasses, pre-ATO collisions, JWT `RS256`→`HS256` &amp; `kid` injection. |
| `08` | <a href="skills/viper-graphql-ws/SKILL.md"><code>viper&#8209;graphql&#8209;ws</code></a> | **GraphQL &amp; WebSocket:** Introspection bypass, field clairvoyance, nested edge BOLA, batching &amp; CSWSH. |
| `09` | <a href="skills/viper-race-logic/SKILL.md"><code>viper&#8209;race&#8209;logic</code></a> | **Race Condition &amp; Logic:** Single-packet HTTP/2 bursts, TOCTOU quota overruns &amp; workflow step skipping. |
| `10` | <a href="skills/viper-taint-sast/SKILL.md"><code>viper&#8209;taint&#8209;sast</code></a> | **White-Box Taint SAST:** Multi-hop source-to-sink code auditing across Python, TS/JS, Go &amp; PHP. |
| `11` | <a href="skills/viper-ai-llm-redteam/SKILL.md"><code>viper&#8209;ai&#8209;llm&#8209;redteam</code></a> | **Agentic AI, LLM &amp; MCP Red-Team:** Indirect prompt injection, tool-call hijacking &amp; RAG exfiltration. |
| `12` | <a href="skills/viper-proof-judge/SKILL.md"><code>viper&#8209;proof&#8209;judge</code></a> | **Adversarial QA Judge:** Enforces *"No Receipt, No Report"*, 7-Question Triage Gate &amp; CVSS 3.1 scoring. |

</details>

---

## 🏆 Benchmarks & Comparison

ViperClaw is continuously validated against **Damn Vulnerable Web Application (DVWA)** across both static source auditing and live containerized HTTP exploitation:

* **White-Box Taint SAST (`viperclaw taint`):** **19 / 19 (100%)** vulnerable modules detected via transitive taint tracking, with **0 False Positives** on hardened `impossible.php` targets (`PDO::prepare`, `intval`, `is_numeric`, `in_array`, `htmlspecialchars`).
* **Black-Box Live Exploitation (`viperclaw scan`):** **14 / 14 (100%)** live vulnerability modules exploited and verified over HTTP in **<5 seconds** with raw wire receipts.

<details>
<summary><b>🔬 View All 14 Wire-Verified DVWA Exploitation Proofs &amp; CVSS v3.1 Vectors</b></summary>
<br />

| # | Severity | Vulnerability&nbsp;Module | Verified Wire Proof / Exploit Vector |
| :---: | :---: | :--- | :--- |
| `01` | **HIGH (8.8)** | OS Command Injection | `ip=127.0.0.1;id` → Verified `uid=33(www-data)` execution |
| `02` | **HIGH (8.1)** | UNION SQL Injection | `' UNION SELECT user,password FROM users#` → Credential hash dump |
| `03` | **MED (6.5)** | Boolean Blind SQLi | True (`1' AND 1=1#`) vs. False (`1' AND 1=2#`) differential oracle |
| `04` | **HIGH (8.1)** | SQLi Auth Bypass | `username=admin' OR '1'='1' LIMIT 1#` → Authenticated admin session |
| `05` | **HIGH (7.1)** | Local File Inclusion | `?page=/etc/passwd` → Verified `root:x:0:0:root:/root:/bin/bash` |
| `06` | **CRIT (9.9)** | Unrestricted Upload RCE | Multipart PHP upload → Verified RCE at `/hackable/uploads/viperclaw_poc.php` |
| `07` | **MED (6.1)** | Reflected XSS | Unescaped HTML payload reflection verified in DOM response |
| `08` | **MED (5.4)** | Stored XSS (Guestbook) | Persistent payload stored in `mtxMessage` and rendered to viewers |
| `09` | **HIGH (8.2)** | Predictable Session ID | Sequential `dvwaSession` $+1$ increment proven across consecutive requests |
| `10` | **HIGH (8.8)** | CSRF Password Reset | State-changing `GET` password reset verified without anti-CSRF token |
| `11` | **MED (6.5)** | CAPTCHA Workflow Bypass | Direct `step=2` state-machine jump verified via auth oracle &amp; restored |
| `12` | **MED (5.4)** | CSP Bypass &amp; Injection | External script injection via permissive `Content-Security-Policy` &amp; `include` |
| `13` | **MED (6.5)** | JS Token Reversal | Reversed `md5(rot13("success"))` client-side token &amp; verified acceptance |
| `14` | **MED (6.1)** | DOM-Based XSS | Unescaped `location.href` sink into `document.write()` verified in browser |

</details>

<details>
<summary><b>📊 View 2026 AI Pentesting Framework Comparison Matrix (ViperClaw vs. Strix, PentAGI, HexStrike, Vulnhuntr)</b></summary>
<br />

| Capability / Architecture | 🐍 ViperClaw | Strix / Shannon | PentAGI / RedAmon | HexStrike AI | Vulnhuntr |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Architecture Pattern** | **Skills + MCP + Engine** | Containerized Agent | Docker + Neo4j Stack | 150-Tool MCP | Python AST CLI |
| **Native Inside Antigravity / Claude / Codex / Cursor** | ✅ **Native** | ⚠️ CLI Wrapper | ⚠️ Partial | ✅ MCP Only | ❌ Standalone |
| **Context-Window Efficiency** | ✅ **8 Phase-Gated Tools** | ✅ Scoped | ✅ Role-Split | ❌ **150+ Dumped** | ✅ Call-Slice |
| **Zero-Setup SQLite Attack Graph + Mermaid** | ✅ **Built-in** | ❌ | ⚠️ Needs Neo4j/PG | ❌ | ❌ |
| **SPA Lazy-Chunk Reconstruction (Webpack/Vite/Next)** | ✅ **Built-in** | ⚠️ Partial | ❌ | ❌ | ❌ |
| **Multi-Language White-Box Taint SAST** | ✅ **Py / TS / Go / PHP** | ✅ Dynamic + Code | ❌ Black-Box | ❌ | ⚠️ **Py 3.10 Only** |
| **Deterministic WAF Soft-200 &amp; BOLA Diff Oracle** | ✅ **Built-in** | ✅ PoC Validation | ⚠️ LLM-Judged | ❌ Raw Stdout | ❌ Static Only |
| **7-Gate Triage + CVSS 3.1 + H1 MD + SARIF 2.1.0** | ✅ **Built-in** | ✅ SARIF | ⚠️ Basic Report | ❌ | ❌ |
| **Runtime Dependencies** | ✅ **0 (Pure Stdlib)** | Docker + Node/LLM | Docker + DB + Kali | 150+ CLI Tools | Python 3.10 + `jedi` |

</details>

<details>
<summary><b>📂 View Repository Structure &amp; Package Layout</b></summary>
<br />

```text
viperclaw/
├── .claude-plugin/               # Claude Code Marketplace & Plugin manifests
├── .github/workflows/ci.yml      # GitHub Actions CI matrix (Python 3.10, 3.11, 3.12)
├── assets/                       # Custom Light-Theme SVG Banner & Architecture Diagrams
├── docs/README.md                # Beginner-to-Pro Complete Usage & Best-Utilization Guide
├── logo.png                      # Lightweight 512x512 transparent square emblem
├── skills/                       # 12 Methodology-Driven Offensive Skills (SKILL.md)
├── src/viperclaw/                # Zero-Dependency Python 3.10+ Core Package
│   ├── cli.py                    # CLI entrypoints (`viperclaw` & `vclaw`)
│   ├── mcp_server.py             # Phase-Gated 8-Tool JSON-RPC 2.0 stdio MCP Server
│   ├── core/                     # Stigmergic Attack Graph, Proof Oracle & SARIF Reporter
│   └── analyzers/                # Live HTTP Scanner, Polyglot Taint SAST, JS & HAR Analyzers
├── tests/test_viperclaw.py       # 10 End-to-End & Adversarial QA Regression Suites
├── CITATION.cff                  # Academic & Research Citation Metadata
├── glama.json                    # MCP Registry Manifest
├── llms.txt                      # AI / LLM Context Discovery Index
└── pyproject.toml                # PEP 621 Zero-Dependency Package Configuration
```

</details>

<details>
<summary><b>❓ Frequently Asked Questions (FAQ)</b></summary>
<br />

* **Why use ViperClaw instead of a standalone Docker pentest agent?**  
  If you already use **Google Antigravity**, **Claude Code**, **OpenAI Codex**, or **Cursor**, spinning up a separate 5-container Docker stack with its own LLM API billing is redundant. ViperClaw installs in 2 seconds with zero dependencies and turns your existing coding agent into an evidence-gated offensive security platform.
* **How does ViperClaw prevent AI hallucinations and WAF "Soft-200" false positives?**  
  Generic AI wrappers often report `200 OK` HTML challenge pages from **Cloudflare, Akamai, Imperva, or CloudFront** as vulnerabilities. ViperClaw's [`ProofOracle`](src/viperclaw/core/oracle.py) filters WAF soft-blocks, diffs structural JSON keys for BOLA/IDOR, and enforces a strict **7-Question Pre-Submission Gate** (*"No Receipt, No Report"*).
* **How do I run the regression test suite?**  
  Run `pytest -v` from the repository root to execute all 10 end-to-end and adversarial QA test suites.

</details>

---

## 📜 Documentation, Security & License

* 📘 **Full User Guide:** [**`docs/README.md`**](docs/README.md) • 🌐 **Website:** [**zahidoverflow.github.io/viperclaw**](https://zahidoverflow.github.io/viperclaw/)
* 🤝 **Contributing & Security Policy:** Review [**`CONTRIBUTING.md`**](CONTRIBUTING.md) and [**`SECURITY.md`**](SECURITY.md).
* ⚠️ **Authorized Use Only:** Developed strictly for authorized security assessments, bug bounty programs with explicit scope permission, educational labs (DVWA / HTB / CTFs), and defensive code auditing.
* ⚖️ **License:** [**MIT License**](LICENSE) — Created by **Zahidul Islam ([@zahidoverflow](https://github.com/zahidoverflow))**.
