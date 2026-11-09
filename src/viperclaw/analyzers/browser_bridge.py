"""
BrowserOS Neo & Live DOM/Storage/Fetch Hook Telemetry Bridge (`viperclaw.analyzers.browser_bridge`).

Bridges live browser sessions (via BrowserOS Neo MCP `evaluate_in_page` or Chrome DevTools Protocol)
into ViperClaw's Stigmergic Attack Graph, JWTEngine, and JSHarvester:
1. Generates ready-to-run JS instrumentation payloads for BrowserOS `evaluate_in_page`:
   - `extract_auth_and_state`: Harvests cookies, localStorage, sessionStorage, JWTs, CSRF tokens,
     Next.js `__NEXT_DATA__`, Nuxt `__NUXT__`, and active DOM scripts/links.
   - `install_runtime_hooks`: Hooks `window.fetch`, `XMLHttpRequest`, and `window.postMessage`
     to capture signed API calls, dynamic headers (`X-Signature`, `X-CSRF-Token`), and DOM sinks.
2. Ingests browser telemetry JSON snapshots into ViperClaw, automatically cracking/analyzing
   discovered JWTs, extracting hidden API routes & IDOR parameters, and populating `AttackGraph`.
"""

from __future__ import annotations

import json
import re
from typing import Any, Dict, List

from viperclaw.analyzers.js_harvester import JSHarvester
from viperclaw.analyzers.jwt_engine import JWTEngine
from viperclaw.core.graph import AttackGraph


JWT_REGEX = re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*")


BROWSER_EXTRACT_SCRIPT = """() => {
  const safeEntries = (store) => {
    const out = {};
    try {
      for (let i = 0; i < store.length; i++) {
        const k = store.key(i);
        out[k] = store.getItem(k);
      }
    } catch (e) {}
    return out;
  };
  const scripts = Array.from(document.querySelectorAll('script[src]')).map(s => s.src);
  const links = Array.from(document.querySelectorAll('a[href]')).map(a => a.href);
  const forms = Array.from(document.querySelectorAll('form')).map(f => ({
    action: f.action || location.href,
    method: (f.method || 'GET').toUpperCase(),
    inputs: Array.from(f.querySelectorAll('input,select,textarea')).map(i => i.name || i.id).filter(Boolean)
  }));
  const metas = {};
  document.querySelectorAll('meta[name],meta[property]').forEach(m => {
    const k = m.getAttribute('name') || m.getAttribute('property');
    if (k) metas[k] = m.getAttribute('content') || '';
  });
  return {
    url: location.href,
    origin: location.origin,
    title: document.title,
    cookies: document.cookie || '',
    localStorage: safeEntries(window.localStorage),
    sessionStorage: safeEntries(window.sessionStorage),
    metas,
    scripts,
    links,
    forms,
    nextData: window.__NEXT_DATA__ ? JSON.stringify(window.__NEXT_DATA__).slice(0, 32768) : null,
    hookedRequests: window.__viperclaw_reqs || []
  };
}"""

BROWSER_HOOK_SCRIPT = """() => {
  if (window.__viperclaw_hooked) return { status: 'already_hooked', captured: (window.__viperclaw_reqs || []).length };
  window.__viperclaw_hooked = true;
  window.__viperclaw_reqs = [];
  const origFetch = window.fetch;
  if (origFetch) {
    window.fetch = async function(...args) {
      try {
        const url = typeof args[0] === 'string' ? args[0] : (args[0] && args[0].url) || '';
        const opts = args[1] || {};
        window.__viperclaw_reqs.push({ type: 'fetch', url, method: opts.method || 'GET', headers: opts.headers || {} });
      } catch (e) {}
      return origFetch.apply(this, args);
    };
  }
  const origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(method, url, ...rest) {
    try {
      window.__viperclaw_reqs.push({ type: 'xhr', method, url });
    } catch (e) {}
    return origOpen.call(this, method, url, ...rest);
  };
  return { status: 'hooks_installed' };
}"""


class BrowserBridge:
    """Ingests live BrowserOS Neo / CDP page telemetry and converts it into offensive leads."""

    @staticmethod
    def get_instrumentation_scripts() -> Dict[str, str]:
        return {
            "extract_auth_and_state": BROWSER_EXTRACT_SCRIPT,
            "install_runtime_hooks": BROWSER_HOOK_SCRIPT,
        }

    @classmethod
    def ingest_snapshot(
        cls,
        snapshot: Dict[str, Any] | str,
        graph_db: str | None = None,
    ) -> Dict[str, Any]:
        if isinstance(snapshot, str):
            try:
                data = json.loads(snapshot)
            except Exception:
                data = {"raw_text": snapshot}
        else:
            data = dict(snapshot)

        serialized = json.dumps(data)
        unescaped_corpus = serialized.replace('\\"', '"').replace("\\/", "/")
        discovered_jwts = list(dict.fromkeys(JWT_REGEX.findall(unescaped_corpus)))
        jwt_analyses: List[Dict[str, Any]] = []
        for tok in discovered_jwts[:5]:
            try:
                rep = JWTEngine.analyze_and_attack(tok)
                jwt_analyses.append(rep.to_dict())
            except Exception:
                continue

        # Run JSHarvester patterns over unescaped corpus (scripts, links, NextData, storage)
        js_bundle_rep = JSHarvester.analyze_content(
            unescaped_corpus,
            source_name=str(data.get("url") or "browser_snapshot"),
            base_url=str(data.get("origin") or ""),
        )

        hooked_reqs = data.get("hookedRequests") if isinstance(data.get("hookedRequests"), list) else []
        hooked_urls = [str(r.get("url")) for r in hooked_reqs if isinstance(r, dict) and r.get("url")]
        all_endpoints = sorted(set(js_bundle_rep.endpoints + hooked_urls))

        csrf_tokens: Dict[str, str] = {}
        metas = data.get("metas") if isinstance(data.get("metas"), dict) else {}
        for mk, mv in metas.items():
            if "csrf" in mk.lower() or "token" in mk.lower():
                csrf_tokens[mk] = str(mv)

        if graph_db:
            graph = AttackGraph(graph_db)
            try:
                page_url = str(data.get("url") or "")
                if page_url:
                    graph.upsert_node("endpoint", page_url, pheromone_boost=2.0)
                for ep in all_endpoints:
                    boost = 5.5 if ep in js_bundle_rep.idor_candidates or ep in js_bundle_rep.ssrf_candidates else 2.5
                    graph.upsert_node("endpoint", ep, pheromone_boost=boost)
                for lc in js_bundle_rep.lazy_chunks:
                    graph.upsert_node("lazy_chunk", lc, pheromone_boost=3.5)
                for j_rep in jwt_analyses:
                    if j_rep.get("cracked_secret"):
                        graph.upsert_node(
                            "finding",
                            f"Cracked JWT HMAC Secret ('{j_rep['cracked_secret']}')",
                            pheromone_boost=20.0,
                            status="verified",
                        )
            finally:
                graph.close()

        return {
            "page_url": data.get("url", ""),
            "cookies_present": bool(data.get("cookies")),
            "local_storage_keys": list((data.get("localStorage") or {}).keys())
            if isinstance(data.get("localStorage"), dict)
            else [],
            "session_storage_keys": list((data.get("sessionStorage") or {}).keys())
            if isinstance(data.get("sessionStorage"), dict)
            else [],
            "csrf_tokens": csrf_tokens,
            "discovered_jwts_count": len(discovered_jwts),
            "jwt_analyses": jwt_analyses,
            "endpoints": all_endpoints,
            "idor_candidates": js_bundle_rep.idor_candidates,
            "ssrf_candidates": js_bundle_rep.ssrf_candidates,
            "lazy_chunks": js_bundle_rep.lazy_chunks,
            "secrets": js_bundle_rep.secrets,
        }
