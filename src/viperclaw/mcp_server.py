"""
Phase-Gated Model Context Protocol (MCP) Server (`viperclaw.mcp_server`).

Why most MCP security bridges (like 150-tool wrappers) fail in practice:
Exposing 150+ raw CLI tool schemas simultaneously bloats the agent's context window,
degrades tool-selection accuracy, and induces noisy scanner behavior.

ViperClaw's MCP server exposes 8 high-signal, methodology-driven tools over standard
JSON-RPC 2.0 (`stdio`), compatible with Antigravity, Claude Code, Codex, Cursor, and Windsurf.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

from viperclaw import __version__
from viperclaw.analyzers.js_harvester import JSHarvester
from viperclaw.analyzers.live_scanner import LiveScanner
from viperclaw.analyzers.proxy_fingerprint import ProxyFingerprinter
from viperclaw.analyzers.taint import TaintAnalyzer
from viperclaw.core.graph import AttackGraph
from viperclaw.core.oracle import HttpSample, ProofOracle
from viperclaw.core.reporter import ReportGenerator, VerifiedFinding


MCP_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "viper_graph_upsert",
        "description": "Upsert a node or edge into the Stigmergic Attack Surface Knowledge Graph and return top pheromone-weighted leads.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace_db": {"type": "string", "description": "Path to SQLite graph DB (default: .viperclaw/graph.db)"},
                "node_type": {"type": "string", "enum": ["host", "endpoint", "parameter", "js_bundle", "lazy_chunk", "auth_role", "taint_sink", "hypothesis", "finding"]},
                "label": {"type": "string", "description": "Node identifier or URL/path"},
                "pheromone_boost": {"type": "number", "description": "Priority boost (0.0 to 50.0)"},
                "status": {"type": "string", "enum": ["untested", "in_progress", "verified", "dead_end"]},
            },
            "required": ["node_type", "label"],
        },
    },
    {
        "name": "viper_graph_leads",
        "description": "Query the highest-pheromone attack leads and Mermaid topology from the Stigmergic Attack Graph.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "workspace_db": {"type": "string", "description": "Path to SQLite graph DB (default: .viperclaw/graph.db)"},
                "limit": {"type": "integer", "default": 15},
                "only_untested": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "viper_harvest_js",
        "description": "Reconstruct Webpack/Vite/Next.js lazy-loaded chunk URLs and extract API endpoints, GraphQL operations, client sinks, and secrets from JS files or directories.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "File or directory path containing JS/TS/HTML/PHP bundles"},
                "base_url": {"type": "string", "description": "Optional asset origin URL to resolve relative lazy chunk paths"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "viper_taint_scan",
        "description": "Run white-box multi-language source-to-sink taint analysis across Python, TypeScript/JS, Go, and PHP to locate RCE, SQLi, SSRF, LFI, Deserialization, XSS, CSRF, and SSTI call chains.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {"type": "string", "description": "Source file or repository directory path"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "viper_fingerprint_traffic",
        "description": "Fingerprint backend frameworks, WAFs, sibling API hosts, error envelopes, and auth mechanisms from a HAR capture or HTTP headers/body.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "har_path": {"type": "string", "description": "Optional path to a .har proxy capture"},
                "url": {"type": "string", "description": "Target URL if fingerprinting a single response"},
                "headers": {"type": "object", "description": "HTTP response headers dictionary"},
                "body": {"type": "string", "description": "HTTP response body snippet"},
            },
        },
    },
    {
        "name": "viper_diff_oracle",
        "description": "Compare baseline vs mutated/cross-tenant HTTP responses to detect WAF soft-blocks, BOLA/IDOR authorization bypasses, and timing anomalies.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "baseline_status": {"type": "integer"},
                "baseline_body": {"type": "string"},
                "probe_status": {"type": "integer"},
                "probe_body": {"type": "string"},
                "unauth_status": {"type": "integer", "description": "Optional unauthenticated status code"},
            },
            "required": ["baseline_status", "baseline_body", "probe_status", "probe_body"],
        },
    },
    {
        "name": "viper_verify_and_report",
        "description": "Run the 7-Question Pre-Submission Triage Gate, calculate CVSS 3.1, and generate a HackerOne/Bugcrowd Markdown report + SARIF 2.1.0 output.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "vuln_class": {"type": "string"},
                "asset": {"type": "string"},
                "request_receipt": {"type": "string"},
                "response_receipt": {"type": "string"},
                "in_scope": {"type": "boolean", "default": True},
                "cross_boundary_proven": {"type": "boolean", "default": True},
            },
            "required": ["title", "vuln_class", "asset", "request_receipt", "response_receipt"],
        },
    },
    {
        "name": "viper_live_scan",
        "description": "Execute a stateful, authenticated HTTP dynamic scan against a live web target or lab (e.g., DVWA), proving exploits over the wire and updating the Stigmergic Attack Graph.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Target base URL"},
                "username": {"type": "string", "default": "admin"},
                "password": {"type": "string", "default": "password"},
                "workspace_db": {"type": "string", "default": ".viperclaw/graph.db"},
            },
            "required": ["url"],
        },
    },
]


def handle_tool_call(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    if name == "viper_graph_upsert":
        db_path = arguments.get("workspace_db", ".viperclaw/graph.db")
        graph = AttackGraph(db_path)
        try:
            node = graph.upsert_node(
                node_type=arguments["node_type"],
                label=arguments["label"],
                pheromone_boost=float(arguments.get("pheromone_boost", 0.0)),
                status=arguments.get("status"),
            )
            return {"upserted": node.to_dict(), "summary": graph.summary()}
        finally:
            graph.close()

    if name == "viper_graph_leads":
        db_path = arguments.get("workspace_db", ".viperclaw/graph.db")
        graph = AttackGraph(db_path)
        try:
            leads = graph.top_leads(
                limit=int(arguments.get("limit", 15)),
                only_untested=bool(arguments.get("only_untested", False)),
            )
            return {
                "top_leads": [n.to_dict() for n in leads],
                "mermaid": graph.export_mermaid(),
            }
        finally:
            graph.close()

    if name == "viper_harvest_js":
        return JSHarvester.analyze_path(
            target_path=arguments["path"],
            base_url=arguments.get("base_url", ""),
        )

    if name == "viper_taint_scan":
        return TaintAnalyzer.scan_path(arguments["path"])

    if name == "viper_fingerprint_traffic":
        har_path = arguments.get("har_path")
        if har_path and Path(har_path).exists():
            return ProxyFingerprinter.analyze_har(har_path).to_dict()
        return ProxyFingerprinter.fingerprint_response(
            url=arguments.get("url", "https://target.local"),
            headers=arguments.get("headers", {}),
            body=arguments.get("body", ""),
        ).to_dict()

    if name == "viper_diff_oracle":
        base = HttpSample(status_code=int(arguments["baseline_status"]), body=arguments["baseline_body"])
        probe = HttpSample(status_code=int(arguments["probe_status"]), body=arguments["probe_body"])
        unauth = (
            HttpSample(status_code=int(arguments["unauth_status"]), body="")
            if "unauth_status" in arguments
            else None
        )
        return ProofOracle.compare_samples(base, probe, unauth).to_dict()

    if name == "viper_verify_and_report":
        triage = ProofOracle.evaluate_7_gates(
            title=arguments["title"],
            evidence_request=arguments["request_receipt"],
            evidence_response=arguments["response_receipt"],
            in_scope=bool(arguments.get("in_scope", True)),
            cross_boundary_proven=bool(arguments.get("cross_boundary_proven", True)),
        )
        finding = VerifiedFinding(
            finding_id="VC-001",
            title=arguments["title"],
            vuln_class=arguments["vuln_class"],
            asset=arguments["asset"],
            cvss_score=triage.cvss_score,
            cvss_severity=triage.cvss_severity,
            cvss_vector=triage.cvss_vector,
            request_receipt=arguments["request_receipt"],
            response_receipt=arguments["response_receipt"],
        )
        return {
            "triage": triage.to_dict(),
            "markdown_report": ReportGenerator.to_bounty_markdown(finding) if triage.passed else None,
        }

    if name == "viper_live_scan":
        scanner = LiveScanner(arguments["url"])
        res = scanner.run_scan(
            username=arguments.get("username", "admin"),
            password=arguments.get("password", "password"),
            graph_db=arguments.get("workspace_db", ".viperclaw/graph.db"),
        )
        return res.to_dict()

    raise ValueError(f"Unknown MCP tool: {name}")


def handle_jsonrpc_message(msg: Dict[str, Any]) -> Dict[str, Any] | None:
    method = msg.get("method")
    msg_id = msg.get("id")

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "viperclaw-mcp", "version": __version__},
            },
        }

    if method == "notifications/initialized":
        return None

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"tools": MCP_TOOLS},
        }

    if method == "tools/call":
        params = msg.get("params", {})
        tool_name = params.get("name", "")
        arguments = params.get("arguments", {})
        try:
            result = handle_tool_call(tool_name, arguments)
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": json.dumps(result, indent=2)}],
                    "isError": False,
                },
            }
        except Exception as exc:
            return {
                "jsonrpc": "2.0",
                "id": msg_id,
                "result": {
                    "content": [{"type": "text", "text": f"Error: {exc}"}],
                    "isError": True,
                },
            }

    if msg_id is not None:
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "error": {"code": -32601, "message": f"Method not found: {method}"},
        }
    return None


def run_stdio_server() -> None:
    """Run the JSON-RPC 2.0 MCP server over stdin/stdout."""
    for raw_line in sys.stdin:
        line = raw_line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        response = handle_jsonrpc_message(msg)
        if response is not None:
            sys.stdout.write(json.dumps(response) + "\n")
            sys.stdout.flush()
