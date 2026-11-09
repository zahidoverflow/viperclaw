"""
ViperClaw Command-Line Interface (`viperclaw` / `vclaw`).

Provides standalone offensive analysis commands, the stdio MCP server, and
a 1-command cross-harness skill installer for Antigravity, Claude Code, Codex, and Cursor.
"""

from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List

from viperclaw import __version__
from viperclaw.analyzers.browser_bridge import BrowserBridge
from viperclaw.analyzers.graphql_engine import GraphQLEngine
from viperclaw.analyzers.js_harvester import JSHarvester
from viperclaw.analyzers.jwt_engine import JWTEngine
from viperclaw.analyzers.live_scanner import LiveScanner
from viperclaw.analyzers.oob_engine import OOBEngine
from viperclaw.analyzers.proxy_fingerprint import ProxyFingerprinter
from viperclaw.analyzers.race_engine import RaceEngine
from viperclaw.analyzers.taint import TaintAnalyzer
from viperclaw.core.graph import AttackGraph
from viperclaw.core.oracle import ProofOracle
from viperclaw.core.reporter import ReportGenerator, VerifiedFinding
from viperclaw.mcp_server import run_stdio_server


BANNER = f"""
╦  ╦╦╔═╗╔═╗╦═╗╔═╗╦  ╔═╗╦ ╦
╚╗╔╝║╠═╝║╣ ╠╦╝║  ║  ╠═╣║║║
 ╚╝ ╩╩  ╚═╝╩╚═╚═╝╩═╝╩ ╩╚╩╝  v{__version__}
Universal AI Offensive Security Harness, Swarm Graph & Proof Oracle
By Zahidul Islam (@zahidoverflow) — MIT License
"""


def get_skills_dir() -> Path:
    repo_root = Path(__file__).resolve().parents[2]
    candidate = repo_root / "skills"
    if candidate.is_dir():
        return candidate
    return Path.cwd() / "skills"


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


def install_skills(target: str, dest_override: str | None = None, dry_run: bool = False) -> Dict[str, Any]:
    home = Path.home()
    target_paths: Dict[str, List[Path]] = {
        "antigravity": [home / ".agents" / "skills"],
        "claude": [home / ".claude" / "skills"],
        "codex": [home / ".codex" / "skills"],
        "cursor": [home / ".cursor" / "skills"],
    }
    if dest_override:
        destinations = [Path(dest_override)]
    elif target == "all":
        destinations = [p[0] for p in target_paths.values()]
    else:
        destinations = target_paths.get(target, [home / ".agents" / "skills"])

    skills = list_available_skills()
    installed: List[str] = []

    for dest_root in destinations:
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="viperclaw",
        description="ViperClaw — Universal AI Offensive Security Harness, Attack Graph, Taint SAST, JS Harvester & Proof Oracle.",
    )
    parser.add_argument("--version", action="version", version=f"viperclaw {__version__}")
    sub = parser.add_subparsers(dest="command")

    # 1. scan (live dynamic HTTP + stateful auth + wire-verified PoCs)
    p_scan = sub.add_parser("scan", help="Run live stateful HTTP scan & wire-verified exploitation against a target URL")
    p_scan.add_argument("url", help="Target base URL (e.g., http://127.0.0.1:4280)")
    p_scan.add_argument("--username", default="admin", help="Optional login username")
    p_scan.add_argument("--password", default="password", help="Optional login password")
    p_scan.add_argument("--cookie", default="", help="Optional raw Cookie header (e.g. 'session=abc; security=low')")
    p_scan.add_argument("--graph-db", "--db", dest="graph_db", default=".viperclaw/graph.db", help="SQLite attack graph path to populate")
    p_scan.add_argument("--sarif-out", "--report-sarif", dest="sarif_out", default="", help="Optional path to write SARIF 2.1.0 report")
    p_scan.add_argument("--report-out", "--report-md", dest="report_out", default="", help="Optional path to write Markdown bounty report bundle")

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

    # 5. race (barrier-synchronized concurrency burst)
    p_race = sub.add_parser("race", help="Run a barrier-synchronized concurrent HTTP race condition burst (TOCTOU)")
    p_race.add_argument("url", help="Target URL for race burst")
    p_race.add_argument("--method", "-X", default="POST", help="HTTP method (default: POST)")
    p_race.add_argument("--body", "-d", default="", help="Request body payload")
    p_race.add_argument("--cookie", default="", help="Optional Cookie header")
    p_race.add_argument("--auth", default="", help="Optional Authorization header (e.g. 'Bearer ...')")
    p_race.add_argument("--concurrency", "-c", type=int, default=15, help="Number of synchronized socket workers (default: 15)")
    p_race.add_argument("--success-indicator", default="", help="Substring indicating a successful state transition")
    p_race.add_argument("--output", "-o", default="", help="Optional output file path for JSON results")

    # 6. jwt (decode, crack HMAC, forge alg:none / kid / confusion & replay)
    p_jwt = sub.add_parser("jwt", help="Decode JWT, crack weak HMAC secrets, synthesize forged tokens & optionally replay")
    p_jwt.add_argument("token", help="JWT token string")
    p_jwt.add_argument("--target-url", default="", help="Optional target URL to replay forged tokens against")
    p_jwt.add_argument("--public-key", default="", help="Optional path to RSA public key PEM for RS256->HS256 confusion")
    p_jwt.add_argument("--output", "-o", default="", help="Optional output file path for JSON results")

    # 7. graphql (introspection bypass, clairvoyance & batching)
    p_gql = sub.add_parser("graphql", help="Scan a GraphQL endpoint for introspection bypass, Clairvoyance field leaks & batching")
    p_gql.add_argument("url", help="GraphQL endpoint URL")
    p_gql.add_argument("--auth", default="", help="Optional Authorization header")
    p_gql.add_argument("--cookie", default="", help="Optional Cookie header")
    p_gql.add_argument("--output", "-o", default="", help="Optional output file path for JSON results")

    # 8. oob (HMAC canary & blind payload matrix)
    p_oob = sub.add_parser("oob", help="Generate HMAC-tagged Out-of-Band (OOB) blind exploit payloads or verify a canary")
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
    p_graph = sub.add_parser("graph", help="Inspect Stigmergic Attack Surface Graph leads or export Mermaid diagram")
    p_graph.add_argument("--db", "--graph-db", dest="db", default=".viperclaw/graph.db", help="Path to SQLite graph DB")
    p_graph.add_argument("--mermaid", action="store_true", help="Output Mermaid flowchart")
    p_graph.add_argument("--top-leads", type=int, default=0, help="Return top N prioritized unverified attack leads")
    p_graph.add_argument("--decay", type=float, default=0.0, help="Apply pheromone evaporation factor (e.g. 0.85)")

    # 12. skills
    p_skills = sub.add_parser("skills", help="List or install the 14 ViperClaw methodology skills for Antigravity, Claude Code, Codex, or Cursor")
    p_skills.add_argument("action", choices=["list", "install"], help="Action to perform")
    p_skills.add_argument("--target", choices=["antigravity", "claude", "codex", "cursor", "all"], default="antigravity")
    p_skills.add_argument("--dest", "--dest-dir", dest="dest", default=None, help="Custom destination directory override")
    p_skills.add_argument("--dry-run", action="store_true", help="Preview installation paths without copying files")

    # 13. mcp
    sub.add_parser("mcp", help="Start the Phase-Gated Model Context Protocol (MCP) JSON-RPC server over stdio")

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
            for ch in res["lazy_chunks"]:
                graph.upsert_node("lazy_chunk", ch, pheromone_boost=2.5)
            for ep in res["endpoints"]:
                boost = 5.0 if ep in res["idor_candidates"] or ep in res["ssrf_candidates"] else 1.5
                graph.upsert_node("endpoint", ep, pheromone_boost=boost)
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
            for fl in res["flows"]:
                label = f"{fl['vuln_class']} @ {fl['file_path']}:{fl['sink_line']}"
                graph.upsert_node("taint_sink", label, pheromone_boost=8.0, metadata=fl)
            graph.close()
        out_str = json.dumps(res, indent=2)
        if args.output:
            Path(args.output).parent.mkdir(parents=True, exist_ok=True)
            Path(args.output).write_text(out_str, encoding="utf-8")
        print(out_str)
        return 0

    if args.command == "fingerprint":
        har_file = Path(args.har_path)
        if not har_file.is_file():
            print(json.dumps({"error": f"HAR file not found: {args.har_path}"}), file=sys.stderr)
            return 2
        report = ProxyFingerprinter.analyze_har(har_file, root_domain=args.domain)
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

    return 0


if __name__ == "__main__":
    sys.exit(main())
