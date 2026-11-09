"""Comprehensive unit and integration test suite for ViperClaw."""

from __future__ import annotations

import base64
import hashlib
import hmac
import http.server
import json
import socketserver
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

from viperclaw.analyzers.browser_bridge import BrowserBridge
from viperclaw.analyzers.graphql_engine import GraphQLEngine
from viperclaw.analyzers.js_harvester import JSHarvester
from viperclaw.analyzers.jwt_engine import JWTEngine
from viperclaw.analyzers.oob_engine import OOBEngine
from viperclaw.analyzers.proxy_fingerprint import ProxyFingerprinter
from viperclaw.analyzers.race_engine import RaceEngine
from viperclaw.analyzers.taint import TaintAnalyzer
from viperclaw.cli import list_available_skills, main
from viperclaw.core.graph import AttackGraph
from viperclaw.core.oracle import HttpSample, ProofOracle
from viperclaw.core.reporter import ReportGenerator, VerifiedFinding
from viperclaw.mcp_server import handle_jsonrpc_message


def test_stigmergic_attack_graph(tmp_path: Path) -> None:
    db_file = tmp_path / "graph.db"
    graph = AttackGraph(db_file)
    try:
        host = graph.upsert_node("host", "api.target.tld", pheromone_boost=2.0)
        ep = graph.upsert_node("endpoint", "/api/v2/users/{id}", pheromone_boost=6.5)
        graph.add_edge(host.node_id, ep.node_id, "HOSTS")

        leads = graph.top_leads(limit=5)
        assert len(leads) == 2
        assert leads[0].label == "/api/v2/users/{id}"
        assert leads[0].pheromone > leads[1].pheromone

        mermaid = graph.export_mermaid()
        assert "flowchart LR" in mermaid
        assert "/api/v2/users/{id}" in mermaid

        decayed = graph.decay_pheromones(0.8)
        assert decayed == 2
    finally:
        graph.close()


def test_proof_oracle_waf_and_bola_diff() -> None:
    cf_block = HttpSample(
        status_code=200,
        body="<html><head><title>Just a moment...</title></head><body>Attention Required! | Cloudflare</body></html>",
    )
    assert ProofOracle.detect_waf_soft_block(cf_block) is not None

    baseline_a = HttpSample(
        status_code=200,
        body=json.dumps({"id": 1001, "email": "alice@tenant-a.com", "role": "owner", "balance": 5000}),
    )
    cross_tenant_b = HttpSample(
        status_code=200,
        body=json.dumps({"id": 1001, "email": "alice@tenant-a.com", "role": "owner", "balance": 5000}),
    )
    unauth = HttpSample(status_code=401, body='{"detail": "Not authenticated"}')

    diff = ProofOracle.compare_samples(baseline_a, cross_tenant_b, unauth)
    assert not diff.is_waf_soft_block
    assert diff.bola_CONFIRMED_hint is True
    assert diff.similarity_ratio == 1.0


def test_proof_oracle_7_gates_and_cvss() -> None:
    verdict_ok = ProofOracle.evaluate_7_gates(
        title="Cross-Tenant BOLA on /api/v1/orgs/{id}/secrets Exposes Production API Keys",
        evidence_request="GET /api/v1/orgs/99/secrets HTTP/1.1\nHost: api.example.com\nAuthorization: Bearer user_b",
        evidence_response='HTTP/1.1 200 OK\n\n{"org_id": 99, "stripe_secret": "REDACTED"}',
        in_scope=True,
        cross_boundary_proven=True,
    )
    assert verdict_ok.passed is True
    assert verdict_ok.verdict == "VERIFIED_SUBMITTABLE"
    assert verdict_ok.cvss_score >= 7.0

    verdict_noise = ProofOracle.evaluate_7_gates(
        title="Missing X-Frame-Options Header on Login Page",
        evidence_request="GET /login HTTP/1.1\nHost: example.com",
        evidence_response="HTTP/1.1 200 OK\nServer: nginx",
    )
    assert verdict_noise.passed is False
    assert verdict_noise.verdict == "REJECTED_NOISE"


def test_js_harvester_lazy_chunks_and_endpoints() -> None:
    sample_js = """
    const chunkMap = {"admin-panel": "9f8e7d6c", "billing-settings": "1a2b3c4d"};
    const lazyLoad = () => import("./chunks/internal-debug.mjs");
    const nextChunk = "_next/static/chunks/pages/admin-778899.js";
    fetch("/api/v2/users/${userId}/invoices?account_id=123");
    fetch("/api/v1/webhooks/test?url=https://internal");
    const gql = `mutation UpdateTenantRole($orgId: ID!) { updateRole(orgId: $orgId) { id } }`;
    window.addEventListener("message", (e) => { element.innerHTML = e.data; });
    """
    res = JSHarvester.analyze_content(sample_js, base_url="https://app.example.com/")
    assert any("admin-panel.9f8e7d6c.chunk.js" in c for c in res.lazy_chunks)
    assert any("internal-debug.mjs" in c for c in res.lazy_chunks)
    assert any("_next/static/chunks/pages/admin-778899.js" in c for c in res.lazy_chunks)
    assert len(res.idor_candidates) >= 1
    assert len(res.ssrf_candidates) >= 1
    assert "mutation UpdateTenantRole" in res.graphql_operations
    assert len(res.client_sinks) >= 2


def test_multi_language_taint_analyzer(tmp_path: Path) -> None:
    vuln_py = tmp_path / "app.py"
    vuln_py.write_text(
        """
import os
from flask import request

def run_diag():
    target_host = request.args.get("host")
    os.system(f"ping -c 1 {target_host}")
""",
        encoding="utf-8",
    )

    vuln_ts = tmp_path / "Controller.ts"
    vuln_ts.write_text(
        """
import { exec } from "child_process";
export function handleWebhook(req: any, res: any) {
    const callbackUrl = req.body.url;
    exec("curl " + callbackUrl);
}
""",
        encoding="utf-8",
    )

    vuln_php = tmp_path / "sqli_multihop.php"
    vuln_php.write_text(
        """<?php
$id = $_REQUEST['id'];
$query = "SELECT first_name FROM users WHERE user_id = '$id';";
$result = mysqli_query($conn, $query);
?>""",
        encoding="utf-8",
    )

    safe_php = tmp_path / "sqli_impossible.php"
    safe_php.write_text(
        """<?php
$id = intval($_GET['id']);
$stmt = $db->prepare('SELECT first_name FROM users WHERE user_id = :id');
$stmt->bindParam(':id', $id, PDO::PARAM_INT);
$stmt->execute();
?>""",
        encoding="utf-8",
    )

    scan = TaintAnalyzer.scan_path(tmp_path)
    assert scan["files_scanned"] == 4
    assert scan["total_flows"] >= 3
    classes = {f["vuln_class"] for f in scan["flows"]}
    assert "Command Injection / RCE" in classes
    assert "SQL Injection (SQLi)" in classes
    flagged_files = {Path(f["file_path"]).name for f in scan["flows"]}
    assert "sqli_impossible.php" not in flagged_files


def test_proxy_fingerprinter() -> None:
    report = ProxyFingerprinter.fingerprint_response(
        url="https://api.target.tld/v1/profile",
        headers={"Server": "cloudflare", "Set-Cookie": "laravel_session=abc; Path=/"},
        body='{"statusCode": 403, "message": "Forbidden resource", "error": "Forbidden"}',
        status_code=403,
    )
    assert "api.target.tld" in report.api_candidate_hosts
    assert any("Laravel" in t for t in report.detected_technologies)
    assert any("NestJS" in t for t in report.detected_technologies)


def test_mcp_server_jsonrpc(tmp_path: Path) -> None:
    init_resp = handle_jsonrpc_message({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert init_resp is not None
    assert init_resp["result"]["serverInfo"]["name"] == "viperclaw-mcp"

    list_resp = handle_jsonrpc_message({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert list_resp is not None
    assert len(list_resp["result"]["tools"]) == 13

    db_path = str(tmp_path / "mcp_graph.db")
    call_resp = handle_jsonrpc_message(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {
                "name": "viper_graph_upsert",
                "arguments": {
                    "workspace_db": db_path,
                    "node_type": "endpoint",
                    "label": "/api/internal/export",
                    "pheromone_boost": 9.5,
                },
            },
        }
    )
    assert call_resp is not None
    assert call_resp["result"]["isError"] is False


def test_all_14_skills_and_cli(tmp_path: Path) -> None:
    skills = list_available_skills()
    assert len(skills) == 14
    for sk in skills:
        text = Path(sk["path"]).read_text(encoding="utf-8")
        assert text.startswith("---\nname: ")
        assert "description:" in text

    rc = main(["skills", "install", "--target", "antigravity", "--dest", str(tmp_path / "skills"), "--dry-run"])
    assert rc == 0

    finding = VerifiedFinding(
        finding_id="VC-100",
        title="Verified SSRF on Webhook Tester",
        vuln_class="SSRF",
        asset="https://api.example.com/webhooks",
        cvss_score=8.6,
        cvss_severity="HIGH",
        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
    )
    sarif_data = ReportGenerator.to_sarif([finding])
    assert sarif_data["version"] == "2.1.0"
    assert len(sarif_data["runs"][0]["results"]) == 1


def test_cli_verify_file_and_python_sanitizer(tmp_path: Path) -> None:
    py_file = tmp_path / "safe_and_vuln.py"
    py_file.write_text(
        """from flask import request
def handler(cursor):
    safe_id = request.args.get("id")
    safe_id = int(safe_id)
    cursor.execute(f"SELECT * FROM items WHERE id = {safe_id}")

    vuln_id = request.GET.get("raw")
    q = f"SELECT * FROM items WHERE name = '{vuln_id}'"
    cursor.execute(q)
""",
        encoding="utf-8",
    )
    flows = TaintAnalyzer.analyze_file(py_file)
    assert len(flows) == 1
    assert flows[0].tainted_vars == ["q"]

    finding_json = tmp_path / "finding.json"
    finding_json.write_text(
        """[{
            "id": "VC-200",
            "title": "Cross-Tenant BOLA on /api/v2/invoices/10042",
            "vuln_class": "BOLA / IDOR",
            "endpoint": "https://api.example.com/api/v2/invoices/10042",
            "cvss_params": {"AV": "N", "AC": "L", "PR": "L", "UI": "N", "S": "U", "C": "H", "I": "N", "A": "N"},
            "receipt": {
                "request_method": "GET",
                "request_url": "https://api.example.com/api/v2/invoices/10042",
                "response_status": 200,
                "response_body": "{\\"invoice_id\\": 10042, \\"customer_email\\": \\"victim@example.com\\"}"
            }
        }]""",
        encoding="utf-8",
    )
    md_out = tmp_path / "out.md"
    sarif_out = tmp_path / "out.sarif"
    rc = main(["verify", str(finding_json), "--report-md", str(md_out), "--report-sarif", str(sarif_out)])
    assert rc == 0
    assert md_out.exists()
    assert sarif_out.exists()


def test_jwt_graphql_race_oob_and_browser_engines(tmp_path: Path) -> None:
    # 1. JWTEngine: create HS256 token signed with 'supersecret', crack it, and forge tokens
    hdr_b64 = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT","kid":"key_1"}').decode().rstrip("=")
    pay_b64 = base64.urlsafe_b64encode(b'{"sub":"user_42","role":"user"}').decode().rstrip("=")
    sig = base64.urlsafe_b64encode(
        hmac.new(b"supersecret", f"{hdr_b64}.{pay_b64}".encode(), hashlib.sha256).digest()
    ).decode().rstrip("=")
    sample_jwt = f"{hdr_b64}.{pay_b64}.{sig}"

    jwt_rep = JWTEngine.analyze_and_attack(sample_jwt, rsa_public_key_pem="-----BEGIN PUBLIC KEY-----\nMIIB...\n")
    assert jwt_rep.cracked_secret == "supersecret"
    assert "alg_none" in jwt_rep.forged_tokens
    assert "cracked_hmac_admin" in jwt_rep.forged_tokens
    assert "kid_dev_null" in jwt_rep.forged_tokens
    assert "rs256_to_hs256_confusion" in jwt_rep.forged_tokens

    # 2. OOBEngine: generate canary, verify HMAC, and test live ephemeral listener
    matrix = OOBEngine.build_payload_matrix("http://127.0.0.1:9999", parameter="webhook_url")
    ssrf_canary = matrix["canaries"]["ssrf"]
    valid, vclass, param = OOBEngine.verify_canary(ssrf_canary)
    assert valid is True and vclass == "ssrf" and param == "webhookurl"

    def _trigger(base_url: str) -> None:
        urllib.request.urlopen(f"{base_url}/{ssrf_canary}", timeout=2.0).read()

    oob_res = OOBEngine.run_ephemeral_listener(trigger_fn=_trigger)
    assert oob_res["verified_hits_count"] == 1
    assert oob_res["hits"][0]["vuln_class"] == "ssrf"

    # 3. BrowserBridge: ingest simulated BrowserOS evaluate_in_page snapshot
    db_file = tmp_path / "browser_graph.db"
    snap = {
        "url": "https://app.target.tld/dashboard",
        "origin": "https://app.target.tld",
        "cookies": f"session={sample_jwt}",
        "localStorage": {"auth_token": sample_jwt},
        "metas": {"csrf-token": "csrf_998877"},
        "nextData": '{"buildId":"123","page":"/admin","chunks":["_next/static/chunks/admin-secret-9911.js"]}',
        "hookedRequests": [{"type": "fetch", "url": "/api/v1/orgs/101/billing?user_id=5", "method": "GET"}],
    }
    ingested = BrowserBridge.ingest_snapshot(snap, graph_db=str(db_file))
    assert ingested["discovered_jwts_count"] == 1
    assert ingested["jwt_analyses"][0]["cracked_secret"] == "supersecret"
    assert any("admin-secret-9911.js" in c for c in ingested["lazy_chunks"])
    assert "/api/v1/orgs/101/billing?user_id=5" in ingested["endpoints"]

    # 4. RaceEngine & GraphQLEngine against an ephemeral local multi-threaded server
    redeemed_flag = {"redeemed": False}

    class _LabHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802
            length = int(self.headers.get("Content-Length") or 0)
            raw_body = self.rfile.read(length).decode("utf-8", errors="replace") if length > 0 else ""
            if self.path == "/api/coupon/redeem":
                if not redeemed_flag["redeemed"]:
                    # Deliberate TOCTOU sleep window before setting flag
                    time.sleep(0.04)
                    redeemed_flag["redeemed"] = True
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'{"status":"COUPON_APPLIED"}')
                else:
                    self.send_response(409)
                    self.end_headers()
                    self.wfile.write(b'{"status":"ALREADY_REDEEMED"}')
                return
            if self.path == "/graphql":
                parsed_gql = json.loads(raw_body)
                if isinstance(parsed_gql, list):
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(json.dumps([{"data": {"__typename": "Query"}} for _ in parsed_gql]).encode())
                    return
                q_str = parsed_gql.get("query", "")
                if "__schema" in q_str:
                    resp_obj = {
                        "data": {
                            "__schema": {
                                "queryType": {"name": "Query"},
                                "mutationType": {"name": "Mutation"},
                                "types": [
                                    {
                                        "kind": "OBJECT",
                                        "name": "Query",
                                        "fields": [{"name": "userAccount", "args": [{"name": "userId"}]}],
                                    }
                                ],
                            }
                        }
                    }
                elif "a15:" in q_str:
                    resp_obj = {"data": {f"a{i}": "Query" for i in range(1, 16)}}
                else:
                    resp_obj = {"errors": [{"message": 'Cannot query field. Did you mean "secretAdminToken" or "userProfile"?'}]}
                self.send_response(200)
                self.end_headers()
                self.wfile.write(json.dumps(resp_obj).encode())
                return

        def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
            return

    class _ThreadedHTTP(socketserver.ThreadingMixIn, http.server.HTTPServer):
        allow_reuse_address = True

    srv = _ThreadedHTTP(("127.0.0.1", 0), _LabHandler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        race_rep = RaceEngine.execute_burst(
            url=f"http://127.0.0.1:{port}/api/coupon/redeem",
            method="POST",
            body="code=VIPER2026",
            concurrency=8,
            success_indicator="COUPON_APPLIED",
            max_expected_successes=1,
        )
        assert race_rep.race_window_proven is True
        assert race_rep.success_count >= 2

        gql_rep = GraphQLEngine.scan_endpoint(f"http://127.0.0.1:{port}/graphql")
        assert gql_rep.introspection_enabled is True
        assert gql_rep.batching_allowed is True
        assert gql_rep.alias_amplification_allowed is True
        assert "Query.userAccount(userId)" in gql_rep.bola_candidate_fields

        suggestions = GraphQLEngine.extract_clairvoyance_suggestions(
            'Cannot query field "admin_vc". Did you mean "secretAdminToken" or "internalConfig"?'
        )
        assert "secretAdminToken" in suggestions
        assert "internalConfig" in suggestions
    finally:
        srv.shutdown()
        srv.server_close()


def test_qa_adversarial_regression_suite(tmp_path: Path) -> None:
    from viperclaw.analyzers.live_scanner import LiveScanner

    bad_har = tmp_path / "corrupt.har"
    bad_har.write_text("{corrupt_json", encoding="utf-8")
    assert ProxyFingerprinter.analyze_har(bad_har).discovered_hosts == []

    null_har = tmp_path / "null.har"
    null_har.write_text('{"log": null}', encoding="utf-8")
    assert ProxyFingerprinter.analyze_har(null_har).discovered_hosts == []

    score, sev, _ = ProofOracle.calculate_cvss31(av="n", ac="l", pr="l", ui="n", scope="u", c="h", i="n", a="n")
    assert score == 6.5 and sev == "MEDIUM"
    score_inv, _, _ = ProofOracle.calculate_cvss31(av="INVALID_METRIC")
    assert score_inv > 0.0

    deep_json = "{" + '"a":{' * 500 + '"val":1' + "}" * 500 + "}"
    v_deep = ProofOracle.compare_samples(HttpSample(200, body=deep_json), HttpSample(200, body=deep_json))
    assert not v_deep.is_waf_soft_block

    err1 = '{"error": "Forbidden", "message": "Access denied to tenant 1", "status": 403}'
    err2 = '{"error": "Forbidden", "message": "Access denied to tenant 2", "status": 403}'
    v_err = ProofOracle.compare_samples(HttpSample(200, body=err1), HttpSample(200, body=err2), HttpSample(401, body=""))
    assert v_err.bola_CONFIRMED_hint is False

    py_edge = tmp_path / "edge.py"
    py_edge.write_text(
        """from flask import request
import os, sys

def aug_and_rebind():
    cmd = "ping "
    cmd += request.args.get("host")
    os.system(cmd)

    rebound = request.args.get("x")
    rebound = "safe_constant"
    os.system(rebound)  # eval(cmd) in comment should not double-trigger

top_arg = sys.argv[1]
os.system(top_arg)
""",
        encoding="utf-8",
    )
    edge_flows = TaintAnalyzer.analyze_file(py_edge)
    assert len(edge_flows) == 2
    sink_vars = {tuple(f.tainted_vars) for f in edge_flows}
    assert ("cmd",) in sink_vars
    assert ("top_arg",) in sink_vars

    js_comment = tmp_path / "comment.js"
    js_comment.write_text("const x = req.query.a;\nconst y = x; // do not call eval(y)\n", encoding="utf-8")
    assert TaintAnalyzer.analyze_file(js_comment) == []

    assert LiveScanner.extract_csrf('<input type="hidden" value="tok_abc" name="csrf_token">') == "tok_abc"
    sc = LiveScanner("http://127.0.0.1:59997", timeout=0.3)
    assert sc.run_scan(graph_db=str(tmp_path / "g.db")).verified_findings == []

    js_sub = JSHarvester.analyze_content('import("chunks/adm.js")', base_url="https://cdn.example.com/subpath")
    assert js_sub.lazy_chunks == ["https://cdn.example.com/subpath/chunks/adm.js"]
