"""
GraphQL Introspection, Clairvoyance Field Suggestion Harvester & Batching Engine (`viperclaw.analyzers.graphql_engine`).

Implements zero-dependency GraphQL offensive discovery and exploitation:
1. Introspection & WAF/Regex Bypass Probes (POST JSON, newline/comment obfuscation, GET query)
2. Clairvoyance Field Suggestion Harvesting (extracts 'Did you mean ...?' schema leaks when introspection is disabled)
3. JSON Array Batching (`[{query}, {query}]`) & Alias Amplification (`{a1:__typename a2:__typename}`) verification
4. Automatic BOLA/IDOR & sensitive mutation candidate extraction.
"""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List


INTROSPECTION_QUERY = (
    "query ViperIntrospection { __schema { queryType { name } mutationType { name } "
    "types { kind name fields(includeDeprecated: true) { name args { name } } } } }"
)

BYPASS_INTROSPECTION_QUERY = (
    "query {\n  __schema\n  {\n    queryType { name }\n    types { name fields { name } }\n  }\n}"
)

CLAIRVOYANCE_PROBES: List[str] = [
    "user",
    "users",
    "me",
    "viewer",
    "admin",
    "account",
    "accounts",
    "organization",
    "org",
    "token",
    "apiKey",
    "secret",
    "config",
    "settings",
    "order",
    "orders",
    "invoice",
    "payment",
    "flag",
    "debug",
]

DID_YOU_MEAN_RE = re.compile(
    r'Did you mean\s+([^?]+)\?',
    re.IGNORECASE,
)

QUOTED_FIELD_RE = re.compile(r'["\']([A-Za-z_][A-Za-z0-9_]*)["\']')


@dataclass
class GraphQLScanReport:
    endpoint_url: str
    introspection_enabled: bool
    introspection_bypass_used: str
    batching_allowed: bool
    alias_amplification_allowed: bool
    discovered_types: List[str] = field(default_factory=list)
    discovered_queries: List[str] = field(default_factory=list)
    discovered_mutations: List[str] = field(default_factory=list)
    clairvoyance_suggested_fields: List[str] = field(default_factory=list)
    bola_candidate_fields: List[str] = field(default_factory=list)
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "endpoint_url": self.endpoint_url,
            "introspection_enabled": self.introspection_enabled,
            "introspection_bypass_used": self.introspection_bypass_used,
            "batching_allowed": self.batching_allowed,
            "alias_amplification_allowed": self.alias_amplification_allowed,
            "discovered_types": self.discovered_types,
            "discovered_queries": self.discovered_queries,
            "discovered_mutations": self.discovered_mutations,
            "clairvoyance_suggested_fields": self.clairvoyance_suggested_fields,
            "bola_candidate_fields": self.bola_candidate_fields,
            "vulnerabilities": self.vulnerabilities,
        }


class GraphQLEngine:
    """Zero-dependency GraphQL introspection, clairvoyance, and batching scanner."""

    @staticmethod
    def _send_gql(
        url: str,
        payload: Any,
        headers: Dict[str, str] | None = None,
        method: str = "POST",
        timeout: float = 6.0,
    ) -> tuple[int, str, Any]:
        req_headers = {
            "User-Agent": "ViperClaw-GraphQLEngine/2.0",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        if headers:
            req_headers.update(headers)

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        data_bytes = None
        target_url = url
        if method.upper() == "GET" and isinstance(payload, dict) and "query" in payload:
            qs = urllib.parse.urlencode({"query": payload["query"]})
            sep = "&" if "?" in url else "?"
            target_url = f"{url}{sep}{qs}"
        else:
            data_bytes = json.dumps(payload).encode("utf-8")

        req = urllib.request.Request(target_url, data=data_bytes, headers=req_headers, method=method.upper())
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
                raw = resp.read(262144).decode("utf-8", errors="replace")
                status = resp.status
        except urllib.error.HTTPError as he:
            status = he.code
            raw = he.read(65536).decode("utf-8", errors="replace")
        except Exception as exc:
            return 0, str(exc), None

        try:
            parsed = json.loads(raw)
        except Exception:
            parsed = None
        return status, raw, parsed

    @classmethod
    def extract_clairvoyance_suggestions(cls, error_messages: List[str] | str) -> List[str]:
        if isinstance(error_messages, list):
            combined = " ".join(str(x) for x in error_messages)
        else:
            combined = str(error_messages)

        suggestions: List[str] = []
        for match in DID_YOU_MEAN_RE.finditer(combined):
            snippet = match.group(1)
            for qm in QUOTED_FIELD_RE.finditer(snippet):
                fname = qm.group(1)
                if fname not in suggestions:
                    suggestions.append(fname)
        return suggestions

    @classmethod
    def scan_endpoint(
        cls,
        url: str,
        headers: Dict[str, str] | None = None,
        probe_clairvoyance: bool = True,
    ) -> GraphQLScanReport:
        introspection_ok = False
        bypass_used = ""
        types_found: List[str] = []
        queries_found: List[str] = []
        mutations_found: List[str] = []
        bola_candidates: List[str] = []
        vulns: List[Dict[str, Any]] = []

        # 1. Standard POST Introspection
        status, raw, parsed = cls._send_gql(url, {"query": INTROSPECTION_QUERY}, headers=headers)
        if not (isinstance(parsed, dict) and isinstance(parsed.get("data"), dict) and "__schema" in parsed["data"]):
            # 2. Try newline bypass
            status2, raw2, parsed2 = cls._send_gql(url, {"query": BYPASS_INTROSPECTION_QUERY}, headers=headers)
            if isinstance(parsed2, dict) and isinstance(parsed2.get("data"), dict) and "__schema" in parsed2["data"]:
                status, raw, parsed = status2, raw2, parsed2
                bypass_used = "newline_whitespace_bypass"
            else:
                # 3. Try GET query-string introspection bypass
                status3, raw3, parsed3 = cls._send_gql(
                    url, {"query": BYPASS_INTROSPECTION_QUERY}, headers=headers, method="GET"
                )
                if isinstance(parsed3, dict) and isinstance(parsed3.get("data"), dict) and "__schema" in parsed3["data"]:
                    status, raw, parsed = status3, raw3, parsed3
                    bypass_used = "http_get_query_bypass"

        if isinstance(parsed, dict) and isinstance(parsed.get("data"), dict) and "__schema" in parsed["data"]:
            introspection_ok = True
            if not bypass_used:
                bypass_used = "standard_post"
            schema = parsed["data"]["__schema"] or {}
            q_type = (schema.get("queryType") or {}).get("name") or "Query"
            m_type = (schema.get("mutationType") or {}).get("name") or "Mutation"
            for t_obj in schema.get("types") or []:
                if not isinstance(t_obj, dict):
                    continue
                tname = str(t_obj.get("name") or "")
                if not tname or tname.startswith("__"):
                    continue
                types_found.append(tname)
                for fld in t_obj.get("fields") or []:
                    if not isinstance(fld, dict):
                        continue
                    fname = str(fld.get("name") or "")
                    args_list = [str(a.get("name") or "") for a in (fld.get("args") or []) if isinstance(a, dict)]
                    if tname == q_type:
                        queries_found.append(fname)
                    elif tname == m_type:
                        mutations_found.append(fname)
                    if any(a.lower() in {"id", "uuid", "userid", "accountid", "orgid", "orderid"} for a in args_list):
                        bola_candidates.append(f"{tname}.{fname}({', '.join(args_list)})")

            vulns.append(
                {
                    "title": f"GraphQL Schema Introspection Exposed ({bypass_used})",
                    "vuln_class": "GraphQL Introspection & Schema Disclosure",
                    "severity": "MEDIUM",
                    "request_receipt": f"POST {url} HTTP/1.1\nContent-Type: application/json\n\n{json.dumps({'query': INTROSPECTION_QUERY})}",
                    "response_receipt": f"HTTP/1.1 {status} OK\nContent-Type: application/json\n\n{raw[:600]}",
                }
            )

        # 2. Clairvoyance Field Suggestion Harvesting
        suggested_fields: List[str] = []
        if probe_clairvoyance and not introspection_ok:
            probe_selection = " ".join(f"{w}_vc_probe" for w in CLAIRVOYANCE_PROBES[:10])
            _, raw_c, parsed_c = cls._send_gql(url, {"query": f"query {{ {probe_selection} }}"}, headers=headers)
            err_texts: List[str] = [raw_c]
            if isinstance(parsed_c, dict) and isinstance(parsed_c.get("errors"), list):
                for e in parsed_c["errors"]:
                    if isinstance(e, dict) and "message" in e:
                        err_texts.append(str(e["message"]))
            suggested_fields = cls.extract_clairvoyance_suggestions(err_texts)
            if suggested_fields:
                vulns.append(
                    {
                        "title": "GraphQL Field Suggestion ('Clairvoyance') Schema Leak",
                        "vuln_class": "GraphQL Field Suggestion Enumeration",
                        "severity": "LOW",
                        "suggested_fields": suggested_fields,
                    }
                )

        # 3. Array Batching Probe (`[{query}, {query}, {query}]`)
        batch_payload = [
            {"query": "query { __typename }"},
            {"query": "query { __typename }"},
            {"query": "query { __typename }"},
        ]
        b_status, b_raw, b_parsed = cls._send_gql(url, batch_payload, headers=headers)
        batching_ok = isinstance(b_parsed, list) and len(b_parsed) == 3 and all(isinstance(x, dict) and "data" in x for x in b_parsed)
        if batching_ok:
            vulns.append(
                {
                    "title": "GraphQL JSON Array Query Batching Enabled (Rate-Limit / Brute-Force Bypass)",
                    "vuln_class": "GraphQL Batching Abuse",
                    "severity": "MEDIUM",
                    "request_receipt": f"POST {url} HTTP/1.1\nContent-Type: application/json\n\n{json.dumps(batch_payload)}",
                    "response_receipt": f"HTTP/1.1 {b_status} OK\nContent-Type: application/json\n\n{b_raw[:400]}",
                }
            )

        # 4. Alias Amplification Probe
        aliases = " ".join(f"a{i}: __typename" for i in range(1, 16))
        a_query = {"query": f"query ViperAliasBurst {{ {aliases} }}"}
        a_status, a_raw, a_parsed = cls._send_gql(url, a_query, headers=headers)
        alias_ok = (
            isinstance(a_parsed, dict)
            and isinstance(a_parsed.get("data"), dict)
            and "a1" in a_parsed["data"]
            and "a15" in a_parsed["data"]
        )

        return GraphQLScanReport(
            endpoint_url=url,
            introspection_enabled=introspection_ok,
            introspection_bypass_used=bypass_used,
            batching_allowed=batching_ok,
            alias_amplification_allowed=alias_ok,
            discovered_types=types_found,
            discovered_queries=queries_found,
            discovered_mutations=mutations_found,
            clairvoyance_suggested_fields=suggested_fields,
            bola_candidate_fields=bola_candidates,
            vulnerabilities=vulns,
        )
