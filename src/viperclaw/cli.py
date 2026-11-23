"""
ViperClaw Command-Line Interface (`viperclaw` / `vclaw`).

Provides standalone application security audit commands, the stdio MCP server, and
a 1-command cross-harness skill installer for Antigravity, Claude Code, Codex, and Cursor.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List

from viperclaw import __version__
from viperclaw.analyzers.browser_bridge import BrowserBridge
from viperclaw.analyzers.graphql_engine import GraphQLEngine
from viperclaw.analyzers.iac_auditor import IaCAuditor
from viperclaw.analyzers.js_harvester import JSHarvester
from viperclaw.analyzers.jwt_engine import JWTEngine
from viperclaw.analyzers.live_scanner import LiveScanner
from viperclaw.analyzers.mcp_auditor import MCPAuditor
from viperclaw.analyzers.oob_engine import OOBEngine
from viperclaw.analyzers.proxy_fingerprint import ProxyFingerprinter
from viperclaw.analyzers.race_engine import RaceEngine
from viperclaw.analyzers.sbom_auditor import SBOMAuditor
from viperclaw.analyzers.secrets_scanner import SecretsScanner
from viperclaw.analyzers.taint import TaintAnalyzer
from viperclaw.core.graph import AttackGraph
from viperclaw.core.oracle import ProofOracle
from viperclaw.core.reporter import ReportGenerator, VerifiedFinding
from viperclaw.mcp_server import run_stdio_server


BANNER = f"""
╦  ╦╦╔═╗╔═╗╦═╗╔═╗╦  ╔═╗╦ ╦
╚╗╔╝║╠═╝║╣ ╠╦╝║  ║  ╠═╣║║║
 ╚╝ ╩╩  ╚═╝╩╚═╚═╝╩═╝╩ ╩╚╩╝  v{__version__}
Application Security Audit Harness, Surface Graph & Evidence Verifier
By Zahidul Islam (@zahidoverflow) — MIT License
"""


DEPRECATED_SKILL_NAMES = ("viper-ai-llm-redteam", "viper-waf-evasion-framing")


def get_skills_dir() -> Path:
    repo_root = Path(__file__).resolve().parents[2]
    for candidate in (
        repo_root / "skills",
        Path(sys.prefix) / "share" / "viperclaw" / "skills",
        Path.home() / ".local" / "share" / "viperclaw" / "skills",
        Path.cwd() / "skills",
    ):
        if candidate.is_dir() and any(candidate.glob("*/SKILL.md")):
            return candidate
    return repo_root / "skills"


def list_available_skills() -> List[Dict[str, str]]:
    skills_root = get_skills_dir()
    skills: List[Dict[str, str]] = []
    if not skills_root.is_dir():
        return skills

    for skill_md in sorted(skills_root.glob("*/SKILL.md")):
        name = skill_md.parent.name
        desc = ""
        for line in skill_md.read_text(encoding="utf-8", errors="ignore").splitlines():
            if line.startswith("description:"):
                desc = line.partition(":")[2].strip()
                break
        skills.append({"name": name, "path": str(skill_md), "description": desc})
    return skills


SUPPORTED_HARNESSES = ("antigravity", "claude", "codex", "cursor", "opencode")


def install_skills(target: str, dest_override: str | None = None, dry_run: bool = False) -> Dict[str, Any]:
    home = Path.home()
    target_paths: Dict[str, List[Path]] = {
        "antigravity": [home / ".gemini" / "config" / "skills"],
        "claude": [home / ".claude" / "skills"],
        "codex": [home / ".codex" / "skills"],
        "cursor": [home / ".cursor" / "skills"],
        "opencode": [home / ".config" / "opencode" / "skills"],
    }
    if dest_override:
        destinations = [Path(dest_override)]
    elif target == "all":
        destinations = [p[0] for p in target_paths.values()]
    else:
        destinations = target_paths.get(target, [home / ".gemini" / "config" / "skills"])

    skills = list_available_skills()
    installed: List[str] = []

    for dest_root in destinations:
        if not dry_run:
            for legacy_name in DEPRECATED_SKILL_NAMES:
                legacy_dir = dest_root / legacy_name
                if legacy_dir.is_dir():
                    shutil.rmtree(legacy_dir)
        for sk in skills:
            src_dir = Path(sk["path"]).parent
            dst_dir = dest_root / sk["name"]
            installed.append(str(dst_dir))
            if not dry_run:
                dst_dir.parent.mkdir(parents=True, exist_ok=True)
                if dst_dir.exists():
                    shutil.rmtree(dst_dir)
                shutil.copytree(src_dir, dst_dir)

    return {
        "target": target,
        "dry_run": dry_run,
        "skills_count": len(skills),
        "installed_paths": installed,
    }


def _upsert_codex_toml_mcp(cfg_path: Path, resolved_bin: str, dry_run: bool = False) -> None:
    """Idempotently upsert [mcp_servers.viperclaw] in OpenAI Codex ~/.codex/config.toml."""
    escaped_bin = resolved_bin.replace("\\", "\\\\").replace('"', '\\"')
    block = (
        "[mcp_servers.viperclaw]\n"
        f'command = "{escaped_bin}"\n'
        'args = ["mcp"]\n'
        "enabled = true\n"
    )
    existing = cfg_path.read_text(encoding="utf-8", errors="ignore") if cfg_path.is_file() else ""
    section_re = re.compile(r"(?ms)^\[mcp_servers\.viperclaw\]\s*\n.*?(?=^\[|\Z)")
    if section_re.search(existing):
        updated = section_re.sub(block + "\n", existing)
    else:
        sep = "\n" if existing and not existing.endswith("\n") else ""
        pad = "\n" if existing.strip() else ""
        updated = f"{existing}{sep}{pad}{block}"
    if not dry_run:
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(updated, encoding="utf-8")


def _upsert_opencode_json_mcp(cfg_path: Path, resolved_bin: str, dry_run: bool = False) -> Dict[str, Any]:
    """Idempotently upsert mcp.viperclaw in OpenCode ~/.config/opencode/opencode.json."""
    stanza = {
        "type": "local",
        "enabled": True,
        "command": [resolved_bin, "mcp"],
    }
    data: Dict[str, Any] = {}
    if cfg_path.is_file():
        try:
            loaded = json.loads(cfg_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except Exception:
            data = {}
    if "$schema" not in data:
        data["$schema"] = "https://opencode.ai/config.json"
    mcp_map = data.get("mcp")
    if not isinstance(mcp_map, dict):
        mcp_map = {}
    mcp_map["viperclaw"] = stanza
    data["mcp"] = mcp_map
    if not dry_run:
        cfg_path.parent.mkdir(parents=True, exist_ok=True)
        cfg_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return stanza


def install_mcp(target: str, dest_override: str | None = None, dry_run: bool = False) -> Dict[str, Any]:
    home = Path.home()
    target_configs: Dict[str, Path] = {
        "antigravity": home / ".gemini" / "config" / "mcp_config.json",
        "claude": home / ".claude.json",
        "codex": home / ".codex" / "config.toml",
        "cursor": home / ".cursor" / "mcp.json",
        "opencode": home / ".config" / "opencode" / "opencode.json",
    }

    resolved_bin = shutil.which("viperclaw") or "viperclaw"
    standard_stanza = {
        "command": resolved_bin,
        "args": ["mcp"],
    }

    if dest_override:
        selected = [(target if target in target_configs else "antigravity", Path(dest_override))]
    elif target == "all":
        selected = list(target_configs.items())
    else:
        key = target if target in target_configs else "antigravity"
        selected = [(key, target_configs[key])]

    updated_files: List[str] = []
    server_entries: Dict[str, Any] = {}

    for harness, cfg_path in selected:
        updated_files.append(str(cfg_path))
        if harness == "opencode":
            server_entries["opencode"] = _upsert_opencode_json_mcp(cfg_path, resolved_bin, dry_run=dry_run)
        elif harness == "codex":
            _upsert_codex_toml_mcp(cfg_path, resolved_bin, dry_run=dry_run)
            server_entries["codex"] = {"command": resolved_bin, "args": ["mcp"], "enabled": True}
        else:
            data: Dict[str, Any] = {}
            if cfg_path.is_file():
                try:
                    loaded = json.loads(cfg_path.read_text(encoding="utf-8"))
                    if isinstance(loaded, dict):
                        data = loaded
                except Exception:
                    data = {}
            servers = data.get("mcpServers")
            if not isinstance(servers, dict):
                servers = {}
            servers["viperclaw"] = standard_stanza
            data["mcpServers"] = servers
            server_entries[harness] = standard_stanza
            if not dry_run:
                cfg_path.parent.mkdir(parents=True, exist_ok=True)
                cfg_path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    return {
        "target": target,
        "dry_run": dry_run,
        "server": {"viperclaw": standard_stanza},
        "harness_configs": server_entries,
        "config_paths": updated_files,
    }


def detect_installed_harnesses(home: Path | None = None) -> List[str]:
    """Detect AI coding harnesses installed on the current machine (always includes opencode on fresh PCs)."""
    h = home or Path.home()
    detected: List[str] = []
    checks = {
        "antigravity": (h / ".gemini").exists() or shutil.which("agy") is not None,
        "claude": (h / ".claude").exists() or (h / ".claude.json").exists() or shutil.which("claude") is not None,
        "codex": (h / ".codex").exists() or shutil.which("codex") is not None,
        "cursor": (h / ".cursor").exists() or shutil.which("cursor") is not None,
        "opencode": (h / ".config" / "opencode").exists() or shutil.which("opencode") is not None,
    }
    for name in SUPPORTED_HARNESSES:
        if checks[name]:
            detected.append(name)
    if "opencode" not in detected:
        detected.append("opencode")
    return detected


def setup_harnesses(target: str = "auto", dry_run: bool = False) -> Dict[str, Any]:
    """One-command fresh-PC setup: installs all ViperClaw skills and registers MCP servers."""
    targets = detect_installed_harnesses() if target == "auto" else (list(SUPPORTED_HARNESSES) if target == "all" else [target])
    skill_results: Dict[str, Any] = {}
    mcp_results: Dict[str, Any] = {}
    for t in targets:
        skill_results[t] = install_skills(t, dry_run=dry_run)
        mcp_results[t] = install_mcp(t, dry_run=dry_run)
    return {
        "mode": target,
        "dry_run": dry_run,
        "configured_harnesses": targets,
        "skills_count": len(list_available_skills()),
        "mcp_config_paths": [mcp_results[t]["config_paths"][0] for t in targets],
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="viperclaw",
        description="ViperClaw — Application Security Audit Harness, Surface Graph, Taint SAST, Bundle Inventory & Evidence Verifier.",
    )
    parser.add_argument("--version", action="version", version=f"viperclaw {__version__}")
    sub = parser.add_subparsers(dest="command")

    # 1. scan (non-destructive HTTP posture + authorized lab verification)
    p_scan = sub.add_parser("scan", help="Inspect live HTTP security posture, CORS/header hygiene, and public API schemas")
    p_scan.add_argument("url", help="Target base URL (https:// optional)")
    p_scan.add_argument("--username", default="admin", help="Optional login username")
    p_scan.add_argument("--password", default="password", help="Optional login password")
    p_scan.add_argument("--cookie", default="", help="Optional raw Cookie header (e.g. 'session=abc; security=low')")
    p_scan.add_argument("--graph-db", "--db", dest="graph_db", default=".viperclaw/graph.db", help="SQLite assessment graph path to populate")
    p_scan.add_argument("--sarif-out", "--report-sarif", dest="sarif_out", default="", help="Optional path to write SARIF 2.1.0 report")
    p_scan.add_argument("--report-out", "--report-md", dest="report_out", default="", help="Optional path to write Markdown compliance report")

    # 2. harvest-js
    p_js = sub.add_parser("harvest-js", help="Extract lazy-loaded chunks, API endpoints, GraphQL ops, sinks & secrets from JS/TS files")
    p_js.add_argument("path", help="Path to JS bundle file or directory")
    p_js.add_argument("--base-url", default="", help="Optional asset base URL to resolve lazy chunk URLs")
    p_js.add_argument("--graph-db", "--db", dest="graph_db", default="", help="Optional SQLite attack graph path to populate")
    p_js.add_argument("--output", "-o", default="", help="Optional output file path for JSON results")

    # 3. taint
    p_taint = sub.add_parser("taint", help="Run multi-language white-box source-to-sink taint analysis (Python, TS/JS, Go, PHP)")
    p_taint.add_argument("path", help="File or repository directory to scan")
    p_taint.add_argument("--graph-db", "--db", dest="graph_db", default="", help="Optional SQLite attack graph path to populate")
    p_taint.add_argument("--output", "-o", default="", help="Optional output file path for JSON results")

    # 4. fingerprint
    p_fp = sub.add_parser("fingerprint", help="Fingerprint API hosts, backend frameworks, and auth mechanisms from a HAR capture")
    p_fp.add_argument("har_path", help="Path to .har file")
    p_fp.add_argument("--domain", "--target-domain", dest="domain", default="", help="Optional root domain filter")
    p_fp.add_argument("--output", "-o", default="", help="Optional output file path for JSON results")

    # 5. race (barrier-synchronized concurrency verification)
    p_race = sub.add_parser("race", help="Verify database locking and idempotency under synchronized HTTP requests (TOCTOU)")
    p_race.add_argument("url", help="Target URL for concurrency verification")
    p_race.add_argument("--method", "-X", default="POST", help="HTTP method (default: POST)")
    p_race.add_argument("--body", "-d", default="", help="Request body")
    p_race.add_argument("--cookie", default="", help="Optional Cookie header")
    p_race.add_argument("--auth", default="", help="Optional Authorization header (e.g. 'Bearer ...')")
    p_race.add_argument("--concurrency", "-c", type=int, default=15, help="Number of synchronized workers (default: 15)")
    p_race.add_argument("--success-indicator", default="", help="Substring indicating a successful state transition")
    p_race.add_argument("--output", "-o", default="", help="Optional output file path for JSON results")

    # 6. jwt (RFC 8725 claim audit, HMAC entropy check & signature edge-case verification)
    p_jwt = sub.add_parser("jwt", help="Audit JWT claims (RFC 8725), HMAC key strength, and signature validation edge cases")
    p_jwt.add_argument("token", help="JWT token string")
    p_jwt.add_argument("--target-url", default="", help="Optional authorized endpoint URL to verify token rejection")
    p_jwt.add_argument("--public-key", default="", help="Optional path to RSA public key PEM for RS256->HS256 algorithm confusion verification")
    p_jwt.add_argument("--output", "-o", default="", help="Optional output file path for JSON results")

    # 7. graphql (introspection, suggestion hints & batching audit)
    p_gql = sub.add_parser("graphql", help="Audit a GraphQL endpoint for schema introspection exposure, field suggestion hints & query batching limits")
    p_gql.add_argument("url", help="GraphQL endpoint URL")
    p_gql.add_argument("--auth", default="", help="Optional Authorization header")
    p_gql.add_argument("--cookie", default="", help="Optional Cookie header")
    p_gql.add_argument("--output", "-o", default="", help="Optional output file path for JSON results")

    # 8. oob (HMAC canary & egress verification)
    p_oob = sub.add_parser("oob", help="Generate HMAC-signed Out-of-Band (OOB) egress verification canaries or verify a canary")
    p_oob.add_argument("--callback", default="http://127.0.0.1:9999", help="Callback base URL (default: http://127.0.0.1:9999)")
    p_oob.add_argument("--param", default="url", help="Target parameter name")
    p_oob.add_argument("--verify-canary", default="", help="Verify an incoming canary token string")

    # 9. browser (BrowserOS Neo bridge)
    p_br = sub.add_parser("browser", help="Output BrowserOS Neo JS instrumentation scripts or ingest a browser DOM/storage snapshot")
    p_br.add_argument("--scripts", action="store_true", help="Output JS snippets for BrowserOS evaluate_in_page")
    p_br.add_argument("--ingest", default="", help="Path to JSON snapshot or raw JSON string from BrowserOS")
    p_br.add_argument("--graph-db", "--db", dest="graph_db", default=".viperclaw/graph.db", help="SQLite attack graph path")

    # 10. verify
    p_ver = sub.add_parser("verify", help="Run the 7-Question Triage Gate & CVSS 3.1 Oracle on a candidate finding or JSON file")
    p_ver.add_argument("finding_file", nargs="?", default="", help="Optional JSON file containing candidate finding(s)")
    p_ver.add_argument("--title", default="", help="Vulnerability title")
    p_ver.add_argument("--vuln-class", default="Broken Object Level Authorization (BOLA/IDOR)", help="Vulnerability category")
    p_ver.add_argument("--asset", default="", help="Target endpoint or file")
    p_ver.add_argument("--request", default="", help="Raw HTTP request or command receipt")
    p_ver.add_argument("--response", default="", help="Raw HTTP response or output receipt")
    p_ver.add_argument("--sarif-out", "--report-sarif", dest="sarif_out", default="", help="Optional path to write SARIF 2.1.0 report")
    p_ver.add_argument("--report-out", "--report-md", dest="report_out", default="", help="Optional path to write Markdown report")

    # 11. graph
    p_graph = sub.add_parser("graph", help="Inspect Stigmergic Assessment Surface Graph leads or export Mermaid diagram")
    p_graph.add_argument("--db", "--graph-db", dest="db", default=".viperclaw/graph.db", help="Path to SQLite graph DB")
    p_graph.add_argument("--mermaid", action="store_true", help="Output Mermaid flowchart")
    p_graph.add_argument("--top-leads", type=int, default=0, help="Return top N prioritized unverified assessment leads")
    p_graph.add_argument("--decay", type=float, default=0.0, help="Apply pheromone evaporation factor (e.g. 0.85)")

    # 12. skills
    p_skills = sub.add_parser("skills", help="List or install all 72 ViperClaw security audit skills for Antigravity, Claude Code, Codex, Cursor, or OpenCode")
    p_skills.add_argument("action", choices=["list", "install"], help="Action to perform")
    p_skills.add_argument("--target", choices=["antigravity", "claude", "codex", "cursor", "opencode", "all"], default="antigravity")
    p_skills.add_argument("--dest", "--dest-dir", dest="dest", default=None, help="Custom destination directory override")
    p_skills.add_argument("--dry-run", action="store_true", help="Preview installation paths without copying files")

    # 13. mcp
    p_mcp = sub.add_parser("mcp", help="Start the Phase-Gated MCP JSON-RPC server or install MCP config")
    sub_mcp = p_mcp.add_subparsers(dest="mcp_action")
    sub_mcp.add_parser("serve", help="Start the MCP stdio server (default when no subcommand is given)")
    p_mcp_install = sub_mcp.add_parser("install", help="Register ViperClaw MCP server in Antigravity, Claude Code, Codex, Cursor, or OpenCode config")
    p_mcp_install.add_argument("--target", choices=["antigravity", "claude", "codex", "cursor", "opencode", "all"], default="antigravity")
    p_mcp_install.add_argument("--dest", "--dest-dir", dest="dest", default=None, help="Custom config file path override")
    p_mcp_install.add_argument("--dry-run", action="store_true", help="Preview MCP config registration without writing")

    # 14. setup (fresh-PC auto-setup for OpenCode + all detected harnesses)
    p_setup = sub.add_parser("setup", help="Auto-configure ViperClaw skills and MCP servers for OpenCode, Antigravity, Claude Code, Codex & Cursor")
    p_setup.add_argument("--target", choices=["auto", "all", "antigravity", "claude", "codex", "cursor", "opencode"], default="auto")
    p_setup.add_argument("--dry-run", action="store_true", help="Preview harness setup without writing files")

    # 15. secrets
    p_sec = sub.add_parser("secrets", help="Scan source files and configs for hardcoded secrets and high-entropy credentials")
    p_sec.add_argument("path", help="File or repository directory to scan")
    p_sec.add_argument("--output", "-o", default="", help="Optional output file path for JSON results")

    # 16. iac
    p_iac = sub.add_parser("iac", help="Audit Dockerfiles, Kubernetes YAML, Terraform (.tf), and GitHub Actions workflows")
    p_iac.add_argument("path", help="File or repository directory to audit")
    p_iac.add_argument("--output", "-o", default="", help="Optional output file path for JSON results")

    # 17. sbom
    p_sbom = sub.add_parser("sbom", help="Generate CycloneDX 1.5 JSON SBOM and audit dependency manifests")
    p_sbom.add_argument("path", help="Manifest file or repository directory to audit")
    p_sbom.add_argument("--output", "-o", default="", help="Optional output file path for JSON results")

    # 18. audit-mcp
    p_amcp = sub.add_parser("audit-mcp", help="Audit MCP JSON configs (opencode.json, mcp_config.json) and SKILL.md bundles")
    p_amcp.add_argument("path", help="MCP config file, skills directory, or repository path")
    p_amcp.add_argument("--output", "-o", default="", help="Optional output file path for JSON results")

    return parser


def _verify_single_item(item: Dict[str, Any]) -> tuple[Any, VerifiedFinding]:
    title = item.get("title", "")
    vuln_class = item.get("vuln_class", "Broken Object Level Authorization (BOLA/IDOR)")
    asset = item.get("asset") or item.get("endpoint") or ""
    finding_id = item.get("id") or item.get("finding_id") or "VC-001"
    receipt = item.get("receipt", {})
    if isinstance(receipt, dict) and receipt:
        req_method = receipt.get("request_method", "GET")
        req_url = receipt.get("request_url", asset)
        req_headers = receipt.get("request_headers", {})
        hdr_lines = "\n".join(f"{k}: {v}" for k, v in req_headers.items())
        req_str = item.get("request") or f"{req_method} {req_url} HTTP/1.1\n{hdr_lines}\n\n{receipt.get('request_body', '')}".strip()
        resp_headers = receipt.get("response_headers", {})
        resp_hdr_lines = "\n".join(f"{k}: {v}" for k, v in resp_headers.items())
        resp_str = item.get("response") or f"HTTP/1.1 {receipt.get('response_status', 200)}\n{resp_hdr_lines}\n\n{receipt.get('response_body', '')}".strip()
    else:
        req_str = item.get("request", "")
        resp_str = item.get("response", "")

    raw_cvss = item.get("cvss_params") or {}
    norm_cvss: Dict[str, str] = {}
    for k, v in raw_cvss.items():
        kl = k.lower()
        if kl == "s":
            norm_cvss["scope"] = str(v).upper()
        elif kl in {"av", "ac", "pr", "ui", "scope", "c", "i", "a"}:
            norm_cvss[kl] = str(v).upper()

    verdict = ProofOracle.evaluate_7_gates(
        title=title,
        evidence_request=req_str,
        evidence_response=resp_str,
        cvss_params=norm_cvss if norm_cvss else None,
    )
    finding = VerifiedFinding(
        finding_id=finding_id,
        title=title,
        vuln_class=vuln_class,
        cwe_id=str(item.get("cwe_id") or "CWE-284"),
        asset=asset,
        cvss_score=verdict.cvss_score,
        cvss_severity=verdict.cvss_severity,
        cvss_vector=verdict.cvss_vector,
        summary=item.get("description") or item.get("summary") or "",
        impact=item.get("impact", ""),
        remediation=item.get("remediation", ""),
        request_receipt=req_str,
        response_receipt=resp_str,
    )
    return verdict, finding


def main(argv: List[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        print(BANNER)
        parser.print_help()
        return 0

    if args.command == "mcp":
        if getattr(args, "mcp_action", None) == "install":
            print(json.dumps(install_mcp(args.target, dest_override=args.dest, dry_run=args.dry_run), indent=2))
            return 0
        run_stdio_server()
        return 0

    if args.command == "scan":
        scanner = LiveScanner(args.url)
        if args.cookie:
            for part in args.cookie.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    scanner.cookies[k.strip()] = v.strip()
        res = scanner.run_scan(
            username=args.username,
            password=args.password,
            graph_db=args.graph_db or None,
        )
        if args.sarif_out:
            Path(args.sarif_out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.sarif_out).write_text(json.dumps(res.sarif, indent=2), encoding="utf-8")
        if args.report_out:
            Path(args.report_out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.report_out).write_text(res.markdown_bundle, encoding="utf-8")
        print(
            json.dumps(
                {
                    "target_url": res.target_url,
                    "authenticated": res.authenticated,
                    "fingerprint": res.fingerprint,
                    "discovered_routes_count": len(res.discovered_routes),
                    "verified_findings_count": len(res.verified_findings),
                    "verified_findings": res.verified_findings,
                },
                indent=2,
            )
        )
        return 0

    if args.command == "harvest-js":
        res = JSHarvester.analyze_path(args.path, base_url=args.base_url)
        if args.graph_db:
            graph = AttackGraph(args.graph_db)
            try:
                for ch in res["lazy_chunks"]:
                    graph.upsert_node("lazy_chunk", ch, pheromone_boost=2.5)
                for ep in res["endpoints"]:
                    boost = 5.0 if ep in res["idor_candidates"] or ep in res["ssrf_candidates"] else 1.5
                    graph.upsert_node("endpoint", ep, pheromone_boost=boost)
            finally:
                graph.close()
        out_str = json.dumps(res, indent=2)
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(out_str, encoding="utf-8")
        print(out_str)
        return 0

    if args.command == "taint":
        res = TaintAnalyzer.scan_path(args.path)
        if args.graph_db:
            graph = AttackGraph(args.graph_db)
            try:
                for fl in res["flows"]:
                    label = f"{fl['vuln_class']} @ {fl['file_path']}:{fl['sink_line']}"
                    graph.upsert_node("taint_sink", label, pheromone_boost=8.0, metadata=fl)
            finally:
                graph.close()
        out_str = json.dumps(res, indent=2)
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(out_str, encoding="utf-8")
        print(out_str)
        return 0

    if args.command == "fingerprint":
        har_file = Path(args.har_path)
        if har_file.is_file():
            report = ProxyFingerprinter.analyze_har(har_file, root_domain=args.domain)
        elif args.har_path.lower().startswith(("http://", "https://")) or (
            "." in args.har_path and not args.har_path.lower().endswith(".har")
        ):
            report = ProxyFingerprinter.fetch_and_fingerprint(args.har_path)
        else:
            print(json.dumps({"error": f"HAR file not found: {args.har_path}"}), file=sys.stderr)
            return 2
        out_str = json.dumps(report.to_dict(), indent=2)
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(out_str, encoding="utf-8")
        print(out_str)
        return 0

    if args.command == "race":
        hdrs: Dict[str, str] = {}
        if args.cookie:
            hdrs["Cookie"] = args.cookie
        if args.auth:
            hdrs["Authorization"] = args.auth
        rep = RaceEngine.execute_burst(
            url=args.url,
            method=args.method,
            headers=hdrs,
            body=args.body,
            concurrency=args.concurrency,
            success_indicator=args.success_indicator,
        )
        out_str = json.dumps(rep.to_dict(), indent=2)
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(out_str, encoding="utf-8")
        print(out_str)
        return 0

    if args.command == "jwt":
        pem = ""
        if args.public_key and Path(args.public_key).is_file():
            pem = Path(args.public_key).read_text(encoding="utf-8")
        rep = JWTEngine.analyze_and_attack(
            token=args.token,
            rsa_public_key_pem=pem,
            target_url=args.target_url,
        )
        out_str = json.dumps(rep.to_dict(), indent=2)
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(out_str, encoding="utf-8")
        print(out_str)
        return 0

    if args.command == "graphql":
        hdrs_gql: Dict[str, str] = {}
        if args.auth:
            hdrs_gql["Authorization"] = args.auth
        if args.cookie:
            hdrs_gql["Cookie"] = args.cookie
        rep = GraphQLEngine.scan_endpoint(args.url, headers=hdrs_gql)
        out_str = json.dumps(rep.to_dict(), indent=2)
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(out_str, encoding="utf-8")
        print(out_str)
        return 0

    if args.command == "oob":
        if args.verify_canary:
            valid, vclass, param = OOBEngine.verify_canary(args.verify_canary)
            print(json.dumps({"valid": valid, "vuln_class": vclass, "parameter": param}, indent=2))
            return 0 if valid else 2
        print(json.dumps(OOBEngine.build_payload_matrix(args.callback, args.param), indent=2))
        return 0

    if args.command == "browser":
        if args.ingest:
            p = Path(args.ingest)
            raw = p.read_text(encoding="utf-8") if p.is_file() else args.ingest
            print(json.dumps(BrowserBridge.ingest_snapshot(raw, graph_db=args.graph_db or None), indent=2))
            return 0
        print(json.dumps(BrowserBridge.get_instrumentation_scripts(), indent=2))
        return 0

    if args.command == "verify":
        items: List[Dict[str, Any]] = []
        if args.finding_file:
            fpath = Path(args.finding_file)
            if not fpath.is_file():
                print(json.dumps({"error": f"Finding JSON file not found: {args.finding_file}"}), file=sys.stderr)
                return 2
            try:
                loaded = json.loads(fpath.read_text(encoding="utf-8"))
            except Exception as exc:
                print(json.dumps({"error": f"Invalid JSON in finding file: {exc}"}), file=sys.stderr)
                return 2
            items = loaded if isinstance(loaded, list) else [loaded]
        else:
            if not (args.title and args.asset and args.request and args.response):
                parser.error("verify requires either a positional finding_file JSON or --title, --asset, --request, and --response")
            items = [
                {
                    "title": args.title,
                    "vuln_class": args.vuln_class,
                    "asset": args.asset,
                    "request": args.request,
                    "response": args.response,
                }
            ]

        verified_list: List[VerifiedFinding] = []
        results_out: List[Dict[str, Any]] = []
        all_passed = True
        for item in items:
            verdict, finding = _verify_single_item(item)
            if verdict.passed:
                verified_list.append(finding)
            else:
                all_passed = False
            results_out.append(
                {
                    "triage": verdict.to_dict(),
                    "markdown_report": ReportGenerator.to_bounty_markdown(finding) if verdict.passed else None,
                }
            )

        if args.sarif_out and verified_list:
            Path(args.sarif_out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.sarif_out).write_text(ReportGenerator.to_sarif_json(verified_list), encoding="utf-8")
        if args.report_out and verified_list:
            md_bundle = "\n\n---\n\n".join(ReportGenerator.to_bounty_markdown(f) for f in verified_list)
            Path(args.report_out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.report_out).write_text(md_bundle, encoding="utf-8")

        output_payload = results_out[0] if len(results_out) == 1 else {"results": results_out}
        print(json.dumps(output_payload, indent=2))
        return 0 if all_passed else 2

    if args.command == "graph":
        graph = AttackGraph(args.db)
        try:
            if args.decay > 0.0:
                graph.decay_pheromones(factor=args.decay)
            if args.mermaid:
                print(graph.export_mermaid())
            elif args.top_leads > 0:
                print(json.dumps([n.to_dict() for n in graph.top_leads(limit=args.top_leads)], indent=2))
            else:
                print(json.dumps(graph.summary(), indent=2))
        finally:
            graph.close()
        return 0

    if args.command == "skills":
        if args.action == "list":
            print(json.dumps(list_available_skills(), indent=2))
        else:
            print(json.dumps(install_skills(args.target, dest_override=args.dest, dry_run=args.dry_run), indent=2))
        return 0

    if args.command == "setup":
        print(json.dumps(setup_harnesses(target=args.target, dry_run=args.dry_run), indent=2))
        return 0

    if args.command in ("secrets", "iac", "sbom", "audit-mcp"):
        scanner_map = {
            "secrets": SecretsScanner.scan_path,
            "iac": IaCAuditor.scan_path,
            "sbom": SBOMAuditor.scan_path,
            "audit-mcp": MCPAuditor.scan_path,
        }
        res = scanner_map[args.command](args.path)
        out_str = json.dumps(res, indent=2)
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(out_str, encoding="utf-8")
        print(out_str)
        return 2 if "error" in res else 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
