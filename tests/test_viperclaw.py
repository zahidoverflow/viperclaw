"""Comprehensive unit and integration test suite for ViperClaw."""

from __future__ import annotations

import json
from pathlib import Path

from viperclaw.analyzers.js_harvester import JSHarvester
from viperclaw.analyzers.proxy_fingerprint import ProxyFingerprinter
from viperclaw.analyzers.taint import TaintAnalyzer
from viperclaw.cli import get_skills_dir, list_available_skills, main
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
    # 1. Valid High/Critical BOLA finding passes all 7 gates
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

    # 2. Scanner noise (missing X-Frame-Options) is automatically rejected
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
    # Confirm sqli_impossible.php produced 0 false positives
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
    assert len(list_resp["result"]["tools"]) == 8

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


def test_all_12_skills_and_cli(tmp_path: Path) -> None:
    skills = list_available_skills()
    assert len(skills) == 12
    for sk in skills:
        text = Path(sk["path"]).read_text(encoding="utf-8")
        assert text.startswith("---\nname: ")
        assert "description:" in text

    rc = main(["skills", "install", "--target", "antigravity", "--dest", str(tmp_path / "skills"), "--dry-run"])
    assert rc == 0

    sarif_file = tmp_path / "out.sarif"
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
