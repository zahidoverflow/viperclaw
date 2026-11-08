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
from typing import Dict, List

from viperclaw import __version__
from viperclaw.analyzers.js_harvester import JSHarvester
from viperclaw.analyzers.proxy_fingerprint import ProxyFingerprinter
from viperclaw.analyzers.taint import TaintAnalyzer
from viperclaw.core.graph import AttackGraph
from viperclaw.core.oracle import HttpSample, ProofOracle
from viperclaw.core.reporter import ReportGenerator, VerifiedFinding
from viperclaw.mcp_server import run_stdio_server


BANNER = r"""
╦  ╦╦╔═╗╔═╗╦═╗╔═╗╦  ╔═╗╦ ╦
╚╗╔╝║╠═╝║╣ ╠╦╝║  ║  ╠═╣║║║
 ╚╝ ╩╩  ╚═╝╩╚═╚═╝╩═╝╩ ╩╚╩╝  v1.0.0
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

    # 1. harvest-js
    p_js = sub.add_parser("harvest-js", help="Extract lazy-loaded chunks, API endpoints, GraphQL ops, sinks & secrets from JS/TS files")
    p_js.add_argument("path", help="Path to JS bundle file or directory")
    p_js.add_argument("--base-url", default="", help="Optional asset base URL to resolve lazy chunk URLs")
    p_js.add_argument("--graph-db", default="", help="Optional SQLite attack graph path to populate")

    # 2. taint
    p_taint = sub.add_parser("taint", help="Run multi-language white-box source-to-sink taint analysis (Python, TS/JS, Go, PHP)")
    p_taint.add_argument("path", help="File or repository directory to scan")
    p_taint.add_argument("--graph-db", default="", help="Optional SQLite attack graph path to populate")

    # 3. fingerprint
    p_fp = sub.add_parser("fingerprint", help="Fingerprint API hosts, backend frameworks, and auth mechanisms from a HAR capture")
    p_fp.add_argument("har_path", help="Path to .har file")
    p_fp.add_argument("--domain", default="", help="Optional root domain filter")

    # 4. verify
    p_ver = sub.add_parser("verify", help="Run the 7-Question Triage Gate & CVSS 3.1 Oracle on a candidate finding")
    p_ver.add_argument("--title", required=True, help="Vulnerability title")
    p_ver.add_argument("--vuln-class", default="Broken Object Level Authorization (BOLA/IDOR)", help="Vulnerability category")
    p_ver.add_argument("--asset", required=True, help="Target endpoint or file")
    p_ver.add_argument("--request", required=True, help="Raw HTTP request or command receipt")
    p_ver.add_argument("--response", required=True, help="Raw HTTP response or output receipt")
    p_ver.add_argument("--sarif-out", default="", help="Optional path to write SARIF 2.1.0 report")

    # 5. graph
    p_graph = sub.add_parser("graph", help="Inspect Stigmergic Attack Surface Graph leads or export Mermaid diagram")
    p_graph.add_argument("--db", default=".viperclaw/graph.db", help="Path to SQLite graph DB")
    p_graph.add_argument("--mermaid", action="store_true", help="Output Mermaid flowchart")

    # 6. skills
    p_skills = sub.add_parser("skills", help="List or install the 12 ViperClaw methodology skills for Antigravity, Claude Code, Codex, or Cursor")
    p_skills.add_argument("action", choices=["list", "install"], help="Action to perform")
    p_skills.add_argument("--target", choices=["antigravity", "claude", "codex", "cursor", "all"], default="antigravity")
    p_skills.add_argument("--dest", default=None, help="Custom destination directory override")
    p_skills.add_argument("--dry-run", action="store_true", help="Preview installation paths without copying files")

    # 7. mcp
    sub.add_parser("mcp", help="Start the Phase-Gated Model Context Protocol (MCP) JSON-RPC server over stdio")

    return parser


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
        print(json.dumps(res, indent=2))
        return 0

    if args.command == "taint":
        res = TaintAnalyzer.scan_path(args.path)
        if args.graph_db:
            graph = AttackGraph(args.graph_db)
            for fl in res["flows"]:
                label = f"{fl['vuln_class']} @ {fl['file_path']}:{fl['sink_line']}"
                graph.upsert_node("taint_sink", label, pheromone_boost=8.0, metadata=fl)
            graph.close()
        print(json.dumps(res, indent=2))
        return 0

    if args.command == "fingerprint":
        report = ProxyFingerprinter.analyze_har(args.har_path, root_domain=args.domain)
        print(json.dumps(report.to_dict(), indent=2))
        return 0

    if args.command == "verify":
        verdict = ProofOracle.evaluate_7_gates(
            title=args.title,
            evidence_request=args.request,
            evidence_response=args.response,
        )
        finding = VerifiedFinding(
            finding_id="VC-001",
            title=args.title,
            vuln_class=args.vuln_class,
            asset=args.asset,
            cvss_score=verdict.cvss_score,
            cvss_severity=verdict.cvss_severity,
            cvss_vector=verdict.cvss_vector,
            request_receipt=args.request,
            response_receipt=args.response,
        )
        if args.sarif_out:
            Path(args.sarif_out).write_text(ReportGenerator.to_sarif_json([finding]), encoding="utf-8")
        out = {
            "triage": verdict.to_dict(),
            "markdown_report": ReportGenerator.to_bounty_markdown(finding) if verdict.passed else None,
        }
        print(json.dumps(out, indent=2))
        return 0 if verdict.passed else 2

    if args.command == "graph":
        graph = AttackGraph(args.db)
        try:
            if args.mermaid:
                print(graph.export_mermaid())
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
