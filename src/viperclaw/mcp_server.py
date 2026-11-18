"""
Phase-Gated Model Context Protocol (MCP) Server (`viperclaw.mcp_server`).

Why most MCP security bridges (like 150-tool wrappers) fail in practice:
Exposing 150+ raw CLI tool schemas simultaneously bloats the agent's context window,
degrades tool-selection accuracy, and induces noisy scanner behavior.

ViperClaw's MCP server exposes 13 high-signal, strict-schema security audit tools over
standard JSON-RPC 2.0 (`stdio`), compatible with Antigravity, Claude Code, Codex, and Cursor.
"""

from __future__ import annotations

import json
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
from viperclaw.core.oracle import HttpSample, ProofOracle
from viperclaw.core.reporter import ReportGenerator, VerifiedFinding


SUPPORTED_PROTOCOL_VERSIONS = {"2024-11-05", "2025-03-26", "2025-06-18"}


MCP_TOOLS: List[Dict[str, Any]] = [
    {
        "name": "viper_graph_upsert",
        "description": "Upsert a node or edge into the Stigmergic Assessment Knowledge Graph and return summary metrics.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "workspace_db": {"type": "string", "maxLength": 512, "description": "Path to SQLite graph DB (default: .viperclaw/graph.db)"},
                "node_type": {"type": "string", "enum": ["host", "endpoint", "parameter", "js_bundle", "lazy_chunk", "auth_role", "taint_sink", "hypothesis", "finding"]},
                "label": {"type": "string", "minLength": 1, "maxLength": 1024, "description": "Node identifier or URL/path"},
                "pheromone_boost": {"type": "number", "minimum": -50.0, "maximum": 100.0, "description": "Priority boost (-50.0 to 100.0)"},
                "status": {"type": "string", "enum": ["untested", "in_progress", "verified", "dead_end"]},
                "metadata": {"type": "object", "description": "Optional structured metadata dictionary"},
            },
            "required": ["node_type", "label"],
        },
    },
    {
        "name": "viper_graph_leads",
        "description": "Query the highest-priority assessment leads, summary statistics, and Mermaid topology from the Stigmergic Graph.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "workspace_db": {"type": "string", "maxLength": 512, "description": "Path to SQLite graph DB (default: .viperclaw/graph.db)"},
                "node_type": {"type": "string", "enum": ["host", "endpoint", "parameter", "js_bundle", "lazy_chunk", "auth_role", "taint_sink", "hypothesis", "finding"], "description": "Optional node type filter"},
                "limit": {"type": "integer", "minimum": 1, "maximum": 200, "default": 15},
                "only_untested": {"type": "boolean", "default": False},
            },
        },
    },
    {
        "name": "viper_harvest_js",
        "description": "Inspect local JS/TS/HTML files, directories, or live web URLs to reconstruct Webpack/Vite/Next.js lazy chunks, routes, DOM sinks, and bundled secrets.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "path": {"type": "string", "minLength": 1, "maxLength": 1024, "description": "Local file/directory path OR live web URL (e.g., https://app.example.com)"},
                "base_url": {"type": "string", "maxLength": 512, "description": "Optional origin URL to resolve relative lazy chunk paths"},
                "workspace_db": {"type": "string", "maxLength": 512, "description": "Optional SQLite graph DB path to populate"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "viper_taint_scan",
        "description": "Run white-box multi-language source-to-sink taint analysis across Python, TypeScript/JS, Go, and PHP to identify unparameterized sinks and verify sanitizers.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "path": {"type": "string", "minLength": 1, "maxLength": 1024, "description": "Source file or repository directory path"},
                "workspace_db": {"type": "string", "maxLength": 512, "description": "Optional SQLite graph DB path to populate"},
            },
            "required": ["path"],
        },
    },
    {
        "name": "viper_fingerprint_traffic",
        "description": "Inspect and fingerprint backend frameworks, CDN/WAF banners, CORS posture, security headers, and error envelopes from a HAR file, raw response data, or live URL.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "har_path": {"type": "string", "maxLength": 1024, "description": "Optional path to a .har proxy capture"},
                "url": {"type": "string", "maxLength": 1024, "description": "Target URL to fetch & fingerprint (https:// optional) or URL label for provided headers/body"},
                "root_domain": {"type": "string", "maxLength": 256, "description": "Optional domain filter when analyzing HAR files"},
                "headers": {"type": "object", "description": "Optional pre-captured HTTP response headers dictionary"},
                "body": {"type": "string", "maxLength": 65536, "description": "Optional pre-captured HTTP response body snippet"},
            },
        },
    },
    {
        "name": "viper_race_burst",
        "description": "Execute a barrier-synchronized concurrent HTTP request burst (pre-connected sockets) to audit TOCTOU concurrency locks and idempotency controls.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "url": {"type": "string", "minLength": 1, "maxLength": 1024, "description": "Target endpoint URL"},
                "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"], "default": "POST"},
                "headers": {"type": "object", "description": "Optional request headers (Cookie, Authorization, Content-Type)"},
                "body": {"type": "string", "maxLength": 16384, "default": "", "description": "Optional request body"},
                "concurrency": {"type": "integer", "minimum": 2, "maximum": 64, "default": 15, "description": "Number of synchronized workers (2-64)"},
                "timeout": {"type": "number", "minimum": 0.5, "maximum": 30.0, "default": 8.0},
                "success_indicator": {"type": "string", "maxLength": 512, "default": "", "description": "Optional substring indicating a successful state transition"},
                "max_expected_successes": {"type": "integer", "minimum": 0, "maximum": 64, "default": 1},
            },
            "required": ["url"],
        },
    },
    {
        "name": "viper_jwt_attack",
        "description": "Audit a JWT header and payload claims, check HMAC secret strength, test signature enforcement edge cases (`alg:none`, `kid`, key confusion), and optionally verify against a target URL.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "token": {"type": "string", "minLength": 5, "maxLength": 16384, "description": "Raw JWT string (header.payload.signature)"},
                "claim_overrides": {"type": "object", "description": "Optional payload claims to test"},
                "custom_secrets": {"type": "array", "items": {"type": "string", "maxLength": 256}, "maxItems": 200, "description": "Optional candidate secrets to test"},
                "rsa_public_key_pem": {"type": "string", "maxLength": 8192, "default": "", "description": "Optional RSA public key PEM for RS256/HS256 confusion verification"},
                "target_url": {"type": "string", "maxLength": 1024, "default": "", "description": "Optional target URL to verify token acceptance"},
            },
            "required": ["token"],
        },
    },
    {
        "name": "viper_graphql_scan",
        "description": "Audit a GraphQL endpoint configuration for schema introspection exposure, field suggestion hints, array query batching, alias limits, and resolver authorization candidates.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "url": {"type": "string", "minLength": 1, "maxLength": 1024, "description": "GraphQL endpoint URL (e.g. api.example.com/graphql)"},
                "headers": {"type": "object", "description": "Optional request headers (Authorization, Cookie)"},
                "probe_clairvoyance": {"type": "boolean", "default": True},
            },
            "required": ["url"],
        },
    },
    {
        "name": "viper_oob_probe",
        "description": "Generate HMAC-authenticated Out-of-Band (OOB) callback verification canaries and test matrices, or cryptographically verify a captured canary.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "callback_base_url": {"type": "string", "maxLength": 512, "default": "http://127.0.0.1:9999", "description": "Base callback URL or authorized listener host"},
                "parameter": {"type": "string", "maxLength": 128, "default": "url", "description": "Target parameter name"},
                "verify_canary": {"type": "string", "maxLength": 256, "default": "", "description": "Optional canary string to cryptographically verify"},
            },
        },
    },
    {
        "name": "viper_browser_ingest",
        "description": "Bridge BrowserOS Neo MCP (`evaluate_in_page`) with ViperClaw: retrieve runtime JS inspection scripts or ingest a browser DOM/storage snapshot into the Assessment Graph.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "action": {"type": "string", "enum": ["get_scripts", "ingest"], "default": "get_scripts"},
                "snapshot": {"type": "object", "description": "JSON snapshot object returned from BrowserOS evaluate_in_page"},
                "snapshot_json": {"type": "string", "maxLength": 524288, "description": "Optional JSON-serialized snapshot string"},
                "workspace_db": {"type": "string", "maxLength": 512, "default": ".viperclaw/graph.db"},
            },
        },
    },
    {
        "name": "viper_diff_oracle",
        "description": "Compare baseline vs. probe HTTP responses to detect WAF soft-blocks, authorization boundary differences, and timing deltas.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "baseline_status": {"type": "integer", "minimum": 0, "maximum": 599},
                "baseline_body": {"type": "string", "maxLength": 262144},
                "baseline_headers": {"type": "object"},
                "probe_status": {"type": "integer", "minimum": 0, "maximum": 599},
                "probe_body": {"type": "string", "maxLength": 262144},
                "probe_headers": {"type": "object"},
                "unauth_status": {"type": "integer", "minimum": 0, "maximum": 599, "description": "Optional unauthenticated HTTP status code"},
                "unauth_body": {"type": "string", "maxLength": 65536, "default": ""},
            },
            "required": ["baseline_status", "baseline_body", "probe_status", "probe_body"],
        },
    },
    {
        "name": "viper_verify_and_report",
        "description": "Run the 7-Question Pre-Submission Quality Gate, calculate CVSS 3.1 scores, and generate HackerOne/Bugcrowd Markdown + SARIF 2.1.0 outputs.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "title": {"type": "string", "minLength": 1, "maxLength": 512},
                "vuln_class": {"type": "string", "minLength": 1, "maxLength": 256},
                "cwe_id": {"type": "string", "maxLength": 32, "default": "CWE-284"},
                "asset": {"type": "string", "minLength": 1, "maxLength": 1024},
                "request_receipt": {"type": "string", "minLength": 1, "maxLength": 65536},
                "response_receipt": {"type": "string", "minLength": 1, "maxLength": 65536},
                "summary": {"type": "string", "maxLength": 4096, "default": ""},
                "impact": {"type": "string", "maxLength": 4096, "default": ""},
                "remediation": {"type": "string", "maxLength": 4096, "default": ""},
                "cvss_params": {"type": "object", "description": "Optional CVSS v3.1 metrics (av, ac, pr, ui, scope, c, i, a)"},
                "in_scope": {"type": "boolean", "default": True},
                "cross_boundary_proven": {"type": "boolean", "default": True},
            },
            "required": ["title", "vuln_class", "asset", "request_receipt", "response_receipt"],
        },
    },
    {
        "name": "viper_live_scan",
        "description": "Run non-destructive API/Web surface discovery, CORS & security header inspection, and authorized lab verification against a target URL, updating the Stigmergic Assessment Graph.",
        "inputSchema": {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "url": {"type": "string", "minLength": 1, "maxLength": 1024, "description": "Target base URL (https:// optional)"},
                "username": {"type": "string", "maxLength": 128, "default": "admin"},
                "password": {"type": "string", "maxLength": 128, "default": "password"},
                "workspace_db": {"type": "string", "maxLength": 512, "default": ".viperclaw/graph.db"},
            },
            "required": ["url"],
        },
    },
]


def _resolve_db_path(arguments: Dict[str, Any]) -> str:
    return str(
        arguments.get("workspace_db")
        or arguments.get("db_path")
        or arguments.get("graph_db")
        or ".viperclaw/graph.db"
    )


def handle_tool_call(name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    arguments = arguments or {}
    if name == "viper_graph_upsert":
        db_path = _resolve_db_path(arguments)
        graph = AttackGraph(db_path)
        try:
            node = graph.upsert_node(
                node_type=arguments["node_type"],
                label=arguments["label"],
                pheromone_boost=float(arguments.get("pheromone_boost", 0.0)),
                status=arguments.get("status"),
                metadata=arguments.get("metadata") if isinstance(arguments.get("metadata"), dict) else None,
            )
            return {"upserted": node.to_dict(), "summary": graph.summary()}
        finally:
            graph.close()

    if name == "viper_graph_leads":
        db_path = _resolve_db_path(arguments)
        graph = AttackGraph(db_path)
        try:
            leads = graph.top_leads(
                limit=int(arguments.get("limit", 15)),
                only_untested=bool(arguments.get("only_untested", False)),
                node_type=arguments.get("node_type"),
            )
            return {
                "top_leads": [n.to_dict() for n in leads],
                "summary": graph.summary(),
                "mermaid": graph.export_mermaid(),
            }
        finally:
            graph.close()

    if name == "viper_harvest_js":
        res = JSHarvester.analyze_path(
            target_path=arguments["path"],
            base_url=arguments.get("base_url", ""),
        )
        db_opt = arguments.get("workspace_db") or arguments.get("db_path") or arguments.get("graph_db")
        if db_opt and res.get("files_scanned", 0) > 0:
            graph = AttackGraph(str(db_opt))
            try:
                for ch in res.get("lazy_chunks", []):
                    graph.upsert_node("lazy_chunk", ch, pheromone_boost=2.5)
                for ep in res.get("endpoints", []):
                    boost = 5.0 if ep in res.get("idor_candidates", []) or ep in res.get("ssrf_candidates", []) else 1.5
                    graph.upsert_node("endpoint", ep, pheromone_boost=boost)
            finally:
                graph.close()
        return res

    if name == "viper_taint_scan":
        res = TaintAnalyzer.scan_path(arguments["path"])
        db_opt = arguments.get("workspace_db") or arguments.get("db_path") or arguments.get("graph_db")
        if db_opt and res.get("flows"):
            graph = AttackGraph(str(db_opt))
            try:
                for fl in res["flows"]:
                    label = f"{fl['vuln_class']} @ {fl['file_path']}:{fl['sink_line']}"
                    graph.upsert_node("taint_sink", label, pheromone_boost=8.0, metadata=fl)
            finally:
                graph.close()
        return res

    if name == "viper_fingerprint_traffic":
        har_path = arguments.get("har_path")
        root_domain = str(arguments.get("root_domain") or arguments.get("domain") or "")
        if har_path:
            if not Path(har_path).is_file():
                return {"error": f"HAR file not found: {har_path}"}
            return ProxyFingerprinter.analyze_har(har_path, root_domain=root_domain).to_dict()

        target_url = str(arguments.get("url") or "").strip()
        has_headers = bool(arguments.get("headers"))
        has_body = bool(arguments.get("body"))
        if target_url and not has_headers and not has_body:
            return ProxyFingerprinter.fetch_and_fingerprint(target_url).to_dict()
        if not target_url and not has_headers and not has_body:
            return {"error": "Provide at least one of: `url`, `har_path`, or pre-captured `headers`/`body`."}
        return ProxyFingerprinter.fingerprint_response(
            url=target_url or "https://target.local",
            headers=arguments.get("headers") or {},
            body=arguments.get("body", ""),
        ).to_dict()

    if name == "viper_race_burst":
        rep = RaceEngine.execute_burst(
            url=arguments["url"],
            method=str(arguments.get("method") or "POST"),
            headers=arguments.get("headers") or {},
            body=str(arguments.get("body") or ""),
            concurrency=int(arguments.get("concurrency", 15)),
            timeout=float(arguments.get("timeout", 8.0)),
            success_indicator=str(arguments.get("success_indicator") or ""),
            max_expected_successes=int(arguments.get("max_expected_successes", 1)),
        )
        return rep.to_dict()

    if name == "viper_jwt_attack":
        rep = JWTEngine.analyze_and_attack(
            token=arguments["token"],
            claim_overrides=arguments.get("claim_overrides"),
            custom_secrets=arguments.get("custom_secrets"),
            rsa_public_key_pem=str(arguments.get("rsa_public_key_pem") or ""),
            target_url=str(arguments.get("target_url") or ""),
        )
        return rep.to_dict()

    if name == "viper_graphql_scan":
        rep = GraphQLEngine.scan_endpoint(
            url=arguments["url"],
            headers=arguments.get("headers") or {},
            probe_clairvoyance=bool(arguments.get("probe_clairvoyance", True)),
        )
        return rep.to_dict()

    if name == "viper_oob_probe":
        verify_str = str(arguments.get("verify_canary") or "")
        if verify_str:
            valid, vclass, param = OOBEngine.verify_canary(verify_str)
            return {"valid": valid, "vuln_class": vclass, "parameter": param}
        return OOBEngine.build_payload_matrix(
            callback_base_url=str(arguments.get("callback_base_url") or "http://127.0.0.1:9999"),
            parameter=str(arguments.get("parameter") or "url"),
        )

    if name == "viper_browser_ingest":
        action = str(arguments.get("action") or "get_scripts")
        snap = arguments.get("snapshot") or arguments.get("snapshot_json")
        if action == "get_scripts" and not snap:
            return BrowserBridge.get_instrumentation_scripts()
        if not snap:
            return {"error": "action='ingest' requires a `snapshot` object or `snapshot_json` string."}
        db_path = arguments.get("workspace_db") or arguments.get("db_path") or arguments.get("graph_db")
        return BrowserBridge.ingest_snapshot(snap, graph_db=db_path)

    if name == "viper_diff_oracle":
        base = HttpSample(
            status_code=int(arguments["baseline_status"]),
            headers=arguments.get("baseline_headers") or {},
            body=arguments["baseline_body"],
        )
        probe = HttpSample(
            status_code=int(arguments["probe_status"]),
            headers=arguments.get("probe_headers") or {},
            body=arguments["probe_body"],
        )
        unauth = (
            HttpSample(
                status_code=int(arguments["unauth_status"]),
                body=str(arguments.get("unauth_body") or ""),
            )
            if "unauth_status" in arguments
            else None
        )
        return ProofOracle.compare_samples(base, probe, unauth).to_dict()

    if name == "viper_verify_and_report":
        raw_cvss = arguments.get("cvss_params") or {}
        norm_cvss: Dict[str, str] = {}
        if isinstance(raw_cvss, dict):
            for k, v in raw_cvss.items():
                kl = k.lower()
                if kl == "s":
                    norm_cvss["scope"] = str(v).upper()
                elif kl in {"av", "ac", "pr", "ui", "scope", "c", "i", "a"}:
                    norm_cvss[kl] = str(v).upper()

        triage = ProofOracle.evaluate_7_gates(
            title=arguments["title"],
            evidence_request=arguments["request_receipt"],
            evidence_response=arguments["response_receipt"],
            cvss_params=norm_cvss if norm_cvss else None,
            in_scope=bool(arguments.get("in_scope", True)),
            cross_boundary_proven=bool(arguments.get("cross_boundary_proven", True)),
        )
        finding = VerifiedFinding(
            finding_id="VC-001",
            title=arguments["title"],
            vuln_class=arguments["vuln_class"],
            cwe_id=str(arguments.get("cwe_id") or "CWE-284"),
            asset=arguments["asset"],
            cvss_score=triage.cvss_score,
            cvss_severity=triage.cvss_severity,
            cvss_vector=triage.cvss_vector,
            summary=str(arguments.get("summary") or ""),
            impact=str(arguments.get("impact") or ""),
            remediation=str(arguments.get("remediation") or ""),
            request_receipt=arguments["request_receipt"],
            response_receipt=arguments["response_receipt"],
        )
        return {
            "triage": triage.to_dict(),
            "markdown_report": ReportGenerator.to_bounty_markdown(finding) if triage.passed else None,
            "sarif": ReportGenerator.to_sarif([finding]) if triage.passed else None,
        }

    if name == "viper_live_scan":
        db_path = _resolve_db_path(arguments)
        scanner = LiveScanner(arguments["url"])
        res = scanner.run_scan(
            username=arguments.get("username", "admin"),
            password=arguments.get("password", "password"),
            graph_db=db_path,
        )
        return res.to_dict()

    raise ValueError(f"Unknown MCP tool: {name}")


def handle_jsonrpc_message(msg: Dict[str, Any]) -> Dict[str, Any] | None:
    if not isinstance(msg, dict):
        return None
    method = str(msg.get("method") or "")
    msg_id = msg.get("id")

    if method.startswith("notifications/"):
        return None

    if method == "initialize":
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        req_proto = str(params.get("protocolVersion") or "2024-11-05")
        proto = req_proto if req_proto in SUPPORTED_PROTOCOL_VERSIONS else "2024-11-05"
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {
                "protocolVersion": proto,
                "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                "serverInfo": {"name": "viperclaw-mcp", "version": __version__},
            },
        }

    if method == "ping":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {}}

    if method == "resources/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"resources": []}}

    if method == "prompts/list":
        return {"jsonrpc": "2.0", "id": msg_id, "result": {"prompts": []}}

    if method == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": msg_id,
            "result": {"tools": MCP_TOOLS},
        }

    if method == "tools/call":
        params = msg.get("params") if isinstance(msg.get("params"), dict) else {}
        tool_name = str(params.get("name") or "")
        arguments = params.get("arguments") if isinstance(params.get("arguments"), dict) else {}
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
    """Run the JSON-RPC 2.0 MCP server over unbuffered stdin/stdout line framing."""
    while True:
        raw_line = sys.stdin.readline()
        if not raw_line:
            break
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
