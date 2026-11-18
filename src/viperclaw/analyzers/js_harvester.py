"""
Deep JavaScript Bundle & Lazy-Chunk Harvester (`viperclaw.analyzers.js_harvester`).

Solves a primary blind spot of generic AI pentesting frameworks:
Modern SPAs (Webpack, Vite, Next.js, Rollup) hide admin panels, internal APIs,
and beta features inside dynamically imported lazy chunks that never load until
a specific route or role check fires.

This module:
1. Reconstructs lazy-loaded JS chunk URLs from Webpack runtime hash maps,
   Vite `import()` tables, and Next.js build manifests.
2. Extracts and classifies API routes (REST, GraphQL queries/mutations, WebSockets).
3. Flags high-value BOLA/IDOR, SSRF, and open-redirect candidate parameters.
4. Detects dangerous DOM/client sinks (`postMessage`, `innerHTML`, `eval`) and leaked secrets.
"""

from __future__ import annotations

import re
import ssl
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Set
from urllib.parse import urljoin, urlsplit

from viperclaw.core.url_utils import normalize_url


ENDPOINT_REGEX = re.compile(
    r"""(?:"|'|`|path:\s*['"]|^\s*)(https?://[^\s"'`<>]+|/(?:api|v[1-9]|vulnerabilities|graphql|gql|internal|admin|auth|oauth|trpc|ws|webhooks?|users?|accounts?|orders?|billing|tenants?|orgs?|files?|upload|export|debug|actuator|swagger|openapi)[^\s"'`<>]*)(?:"|'|`)?""",
    re.IGNORECASE | re.MULTILINE,
)

GRAPHQL_OP_REGEX = re.compile(
    r"""\b(query|mutation|subscription)\s+([A-Za-z0-9_]{2,64})\s*(?:\(|{)""",
)

VITE_DYNAMIC_IMPORT_REGEX = re.compile(
    r"""import\(\s*["'`]([^"'`]+\.m?js)["'`]\s*\)"""
)

NEXT_CHUNK_REGEX = re.compile(
    r"""["'](/?(?:static/chunks/|_next/static/chunks/)[^"']+\.js)["']"""
)

WEBPACK_CHUNK_MAP_REGEX = re.compile(
    r"""\{(?:\s*["']?[a-zA-Z0-9_-]+["']?\s*:\s*["'][a-f0-9]{6,32}["']\s*,?)+\}"""
)

WEBPACK_PAIR_REGEX = re.compile(
    r"""["']?([a-zA-Z0-9_-]+)["']?\s*:\s*["']([a-f0-9]{6,32})["']"""
)

CLIENT_SINK_PATTERNS = [
    ("postMessage_listener", re.compile(r"""addEventListener\(\s*["']message["']""")),
    ("dangerouslySetInnerHTML", re.compile(r"""dangerouslySetInnerHTML""")),
    ("dom_innerHTML", re.compile(r"""\.innerHTML\s*=""")),
    ("dom_outerHTML", re.compile(r"""\.outerHTML\s*=""")),
    ("document_write", re.compile(r"""document\.write(?:ln)?\(""")),
    ("eval_call", re.compile(r"""\beval\s*\(""")),
    ("location_assign", re.compile(r"""(?:window\.)?location(?:\.href|\.replace|\.assign)?\s*=""")),
]

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"""\b(AKIA[0-9A-Z]{16})\b""")),
    ("Google API Key", re.compile(r"""\b(AIza[0-9A-Za-z\-_]{35})\b""")),
    ("Stripe Live/Test Key", re.compile(r"""\b((?:sk|rk)_(?:live|test)_[0-9a-zA-Z]{24,99})\b""")),
    ("Slack Token", re.compile(r"""\b(xox[baprs]-[0-9a-zA-Z\-]{10,72})\b""")),
    ("GitHub PAT", re.compile(r"""\b(gh[pousr]_[A-Za-z0-9_]{36,255})\b""")),
    ("Private JWT", re.compile(r"""\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b""")),
    ("Firebase URL", re.compile(r"""(https://[a-z0-9-]+\.firebaseio\.com)""")),
]

IDOR_PARAM_HINTS = {"id", "uid", "user_id", "userid", "account_id", "org_id", "tenant_id", "order_id", "invoice_id", "doc_id"}
SSRF_PARAM_HINTS = {"url", "uri", "webhook", "callback", "dest", "redirect", "proxy", "target", "endpoint", "fetch"}


@dataclass
class JSHarvestResult:
    source_name: str
    lazy_chunks: List[str] = field(default_factory=list)
    endpoints: List[str] = field(default_factory=list)
    idor_candidates: List[str] = field(default_factory=list)
    ssrf_candidates: List[str] = field(default_factory=list)
    graphql_operations: List[str] = field(default_factory=list)
    client_sinks: List[Dict[str, Any]] = field(default_factory=list)
    secrets: List[Dict[str, str]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class JSHarvester:
    """Reconstructs lazy chunks and harvests endpoints, sinks, and secrets from JS bundles."""

    @classmethod
    def analyze_content(
        cls,
        content: str,
        source_name: str = "bundle.js",
        base_url: str = "",
        chunk_prefix: str = "static/js/",
    ) -> JSHarvestResult:
        chunks: Set[str] = set()
        norm_base = (normalize_url(base_url).rstrip("/") + "/") if base_url else ""

        # 1. Vite / ES dynamic import() chunks
        for m in VITE_DYNAMIC_IMPORT_REGEX.finditer(content):
            raw = m.group(1)
            chunks.add(urljoin(norm_base, raw) if norm_base else raw)

        # 2. Next.js chunks
        for m in NEXT_CHUNK_REGEX.finditer(content):
            raw = m.group(1).lstrip("/")
            chunks.add(urljoin(norm_base, raw) if norm_base else raw)

        # 3. Webpack chunk ID -> hash map reconstruction
        for map_match in WEBPACK_CHUNK_MAP_REGEX.finditer(content):
            block = map_match.group(0)
            for pair in WEBPACK_PAIR_REGEX.finditer(block):
                cid, chash = pair.group(1), pair.group(2)
                rel_path = f"{chunk_prefix.rstrip('/')}/{cid}.{chash}.chunk.js"
                chunks.add(urljoin(norm_base, rel_path) if norm_base else rel_path)

        # 4. Endpoints & classification
        endpoints: Set[str] = set()
        idor_leads: Set[str] = set()
        ssrf_leads: Set[str] = set()

        for m in ENDPOINT_REGEX.finditer(content):
            ep = m.group(1).strip()
            if any(ep.endswith(ext) for ext in (".png", ".svg", ".webp", ".woff2", ".css", ".ico")):
                continue
            endpoints.add(ep)
            ep_lower = ep.lower()
            if (
                re.search(r"/(?:users?|accounts?|orders?|tenants?|orgs?|invoices?|documents?)/(?:\$\{|:[a-zA-Z]|\[)", ep_lower)
                or any(f"{p}=" in ep_lower for p in IDOR_PARAM_HINTS)
            ):
                idor_leads.add(ep)
            if any(f"{p}=" in ep_lower or f"/{p}" in ep_lower for p in SSRF_PARAM_HINTS):
                ssrf_leads.add(ep)

        # 5. GraphQL operations
        gql_ops: Set[str] = set()
        for m in GRAPHQL_OP_REGEX.finditer(content):
            gql_ops.add(f"{m.group(1)} {m.group(2)}")

        # 6. Client DOM / postMessage sinks
        sinks: List[Dict[str, Any]] = []
        for sink_name, pattern in CLIENT_SINK_PATTERNS:
            matches = list(pattern.finditer(content))
            if matches:
                sinks.append({"sink": sink_name, "count": len(matches)})

        # 7. High-signal secrets
        secrets: List[Dict[str, str]] = []
        seen_secrets: Set[str] = set()
        for label, pattern in SECRET_PATTERNS:
            for m in pattern.finditer(content):
                val = m.group(1)
                if val not in seen_secrets:
                    seen_secrets.add(val)
                    secrets.append({"type": label, "value": val})

        return JSHarvestResult(
            source_name=source_name,
            lazy_chunks=sorted(chunks),
            endpoints=sorted(endpoints),
            idor_candidates=sorted(idor_leads),
            ssrf_candidates=sorted(ssrf_leads),
            graphql_operations=sorted(gql_ops),
            client_sinks=sinks,
            secrets=secrets,
        )

    @staticmethod
    def _looks_like_url(target: str) -> bool:
        s = target.strip()
        lower = s.lower()
        if lower.startswith(("http://", "https://")):
            return True
        if s.startswith(("/", "./", "../", "~")) or Path(s).exists():
            return False
        host_part = s.split("/", 1)[0].split(":", 1)[0]
        return "." in host_part and not any(
            host_part.lower().endswith(ext)
            for ext in (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".html", ".php", ".yml", ".yaml", ".json")
        )

    @classmethod
    def analyze_url(
        cls,
        target_url: str,
        max_scripts: int = 20,
        timeout: float = 8.0,
    ) -> Dict[str, Any]:
        norm_url = normalize_url(target_url)
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        def _fetch(u: str, max_bytes: int = 2_097_152) -> str:
            req = urllib.request.Request(
                u,
                headers={"User-Agent": "ViperClaw-JSHarvester/2.0", "Accept": "text/html,application/javascript,*/*"},
            )
            try:
                with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
                    return resp.read(max_bytes).decode("utf-8", errors="ignore")
            except urllib.error.HTTPError as he:
                return he.read(min(max_bytes, 65536)).decode("utf-8", errors="ignore") if he.fp else ""
            except Exception:
                return ""

        root_html = _fetch(norm_url)
        if not root_html:
            return {
                "target_url": norm_url,
                "files_scanned": 0,
                "lazy_chunks": [],
                "endpoints": [],
                "idor_candidates": [],
                "ssrf_candidates": [],
                "graphql_operations": [],
                "client_sinks": [],
                "secrets": [],
                "error": f"Unable to fetch HTML/JS content from {norm_url}",
            }

        origin = f"{urlsplit(norm_url).scheme}://{urlsplit(norm_url).netloc}"
        script_srcs = re.findall(r"""<script[^>]+src=["']([^"']+)["']""", root_html, re.IGNORECASE)
        script_urls: List[str] = []
        for s in script_srcs:
            abs_u = urljoin(norm_url, s)
            if abs_u not in script_urls:
                script_urls.append(abs_u)
        script_urls = script_urls[:max_scripts]

        sources: List[tuple[str, str]] = [(norm_url, root_html)]
        for su in script_urls:
            body = _fetch(su)
            if body:
                sources.append((su, body))

        all_chunks: Set[str] = set()
        all_endpoints: Set[str] = set()
        all_idor: Set[str] = set()
        all_ssrf: Set[str] = set()
        all_gql: Set[str] = set()
        all_sinks: List[Dict[str, Any]] = []
        all_secrets: List[Dict[str, str]] = []

        for src_name, text in sources:
            res = cls.analyze_content(text, source_name=src_name, base_url=origin)
            all_chunks.update(res.lazy_chunks)
            all_endpoints.update(res.endpoints)
            all_idor.update(res.idor_candidates)
            all_ssrf.update(res.ssrf_candidates)
            all_gql.update(res.graphql_operations)
            for sk in res.client_sinks:
                all_sinks.append({"file": src_name, **sk})
            for sec in res.secrets:
                all_secrets.append({"file": src_name, **sec})

        return {
            "target_url": norm_url,
            "fetched_scripts": [u for u, _ in sources[1:]],
            "files_scanned": len(sources),
            "lazy_chunks": sorted(all_chunks),
            "endpoints": sorted(all_endpoints),
            "idor_candidates": sorted(all_idor),
            "ssrf_candidates": sorted(all_ssrf),
            "graphql_operations": sorted(all_gql),
            "client_sinks": all_sinks,
            "secrets": all_secrets,
        }

    @classmethod
    def analyze_path(cls, target_path: str | Path, base_url: str = "") -> Dict[str, Any]:
        if isinstance(target_path, str) and cls._looks_like_url(target_path):
            return cls.analyze_url(target_path)

        path = Path(target_path)
        if not path.exists():
            return {
                "files_scanned": 0,
                "lazy_chunks": [],
                "endpoints": [],
                "idor_candidates": [],
                "ssrf_candidates": [],
                "graphql_operations": [],
                "client_sinks": [],
                "secrets": [],
                "error": f"Path not found: {target_path}. Pass an existing local file/directory or a live URL (e.g., https://app.example.com).",
            }

        files: List[Path] = []
        if path.is_file():
            files = [path]
        elif path.is_dir():
            files = sorted(
                p
                for p in path.rglob("*")
                if p.is_file()
                and p.suffix.lower() in {".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".html", ".php", ".yml", ".yaml"}
                and not any(skip in p.parts for skip in ("node_modules", ".git", ".venv", "venv"))
            )

        all_chunks: Set[str] = set()
        all_endpoints: Set[str] = set()
        all_idor: Set[str] = set()
        all_ssrf: Set[str] = set()
        all_gql: Set[str] = set()
        all_sinks: List[Dict[str, Any]] = []
        all_secrets: List[Dict[str, str]] = []

        for fpath in files:
            try:
                text = fpath.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            res = cls.analyze_content(text, source_name=str(fpath), base_url=base_url)
            all_chunks.update(res.lazy_chunks)
            all_endpoints.update(res.endpoints)
            all_idor.update(res.idor_candidates)
            all_ssrf.update(res.ssrf_candidates)
            all_gql.update(res.graphql_operations)
            for s in res.client_sinks:
                all_sinks.append({"file": str(fpath), **s})
            for sec in res.secrets:
                all_secrets.append({"file": str(fpath), **sec})

        return {
            "files_scanned": len(files),
            "lazy_chunks": sorted(all_chunks),
            "endpoints": sorted(all_endpoints),
            "idor_candidates": sorted(all_idor),
            "ssrf_candidates": sorted(all_ssrf),
            "graphql_operations": sorted(all_gql),
            "client_sinks": all_sinks,
            "secrets": all_secrets,
        }
