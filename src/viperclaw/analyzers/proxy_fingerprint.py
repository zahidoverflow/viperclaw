"""
HTTP Stack & Proxy Traffic Fingerprinter (`viperclaw.analyzers.proxy_fingerprint`).

Applies multi-signal HTTP fingerprinting heuristics across live responses or
exported HAR / Caido / Burp proxy captures:
1. Header & banner signatures (`Server`, `X-Powered-By`, `Via`, tracing headers)
2. Cookie naming conventions (`laravel_session`, `connect.sid`, `JSESSIONID`, `csrftoken`)
3. Error response JSON shapes (`detail`, `statusCode+message+error`, `errors[].extensions`)
4. Sibling API host and auth-scheme extraction from HAR files
"""

from __future__ import annotations

import json
import re
import ssl
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Set
from urllib.parse import urlparse

from viperclaw.core.url_utils import normalize_url


COOKIE_TECH_MAP = {
    "phpsessid": "PHP",
    "laravel_session": "Laravel (PHP)",
    "xsrf-token": "Laravel / Angular CSRF",
    "csrftoken": "Django (Python)",
    "sessionid": "Django (Python)",
    "connect.sid": "Express / Node.js",
    "jsessionid": "Java (Spring / Tomcat / Jetty)",
    "asp.net_sessionid": "ASP.NET (.NET)",
    ".aspnetcore.cookies": "ASP.NET Core",
    "rack.session": "Ruby (Rack / Rails)",
    "_rails_session": "Ruby on Rails",
}

HEADER_TECH_MAP = {
    "x-powered-by": "Backend Runtime Banner",
    "server": "Web Server / Reverse Proxy",
    "x-aspnet-version": "ASP.NET",
    "x-drupal-cache": "Drupal CMS",
    "x-generator": "Generator Banner",
    "x-amz-cf-id": "AWS CloudFront CDN",
    "x-amzn-requestid": "AWS API Gateway / ALB",
    "cf-ray": "Cloudflare CDN / WAF",
    "x-vercel-id": "Vercel Edge / Next.js",
    "fly-request-id": "Fly.io Edge",
}


@dataclass
class FingerprintReport:
    target: str
    discovered_hosts: List[str] = field(default_factory=list)
    api_candidate_hosts: List[str] = field(default_factory=list)
    detected_technologies: List[str] = field(default_factory=list)
    auth_mechanisms: List[str] = field(default_factory=list)
    error_shape_hints: List[str] = field(default_factory=list)
    high_value_endpoints: List[str] = field(default_factory=list)
    security_posture: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ProxyFingerprinter:
    """Fingerprints backend technology stacks, API hosts, and auth schemes from HTTP data or HAR."""

    @classmethod
    def fingerprint_response(
        cls,
        url: str,
        headers: Dict[str, str],
        body: str = "",
        status_code: int = 200,
    ) -> FingerprintReport:
        parsed = urlparse(normalize_url(url))
        host = parsed.netloc or parsed.path
        techs: Set[str] = set()
        auths: Set[str] = set()
        error_hints: Set[str] = set()

        lower_headers = {k.lower(): v for k, v in headers.items()}
        for h_key, label in HEADER_TECH_MAP.items():
            if h_key in lower_headers:
                techs.add(f"{label}: {lower_headers[h_key]}")

        set_cookie = lower_headers.get("set-cookie", "").lower()
        for cookie_name, framework in COOKIE_TECH_MAP.items():
            if cookie_name in set_cookie:
                techs.add(framework)
                auths.add(f"Session Cookie ({cookie_name})")

        if "www-authenticate" in lower_headers:
            auths.add(f"WWW-Authenticate: {lower_headers['www-authenticate']}")

        # Inspect JSON error shapes (FastAPI, NestJS, Spring Boot, GraphQL, Rails)
        try:
            data = json.loads(body)
            if isinstance(data, dict):
                keys = set(data.keys())
                if keys == {"detail"} or ("detail" in keys and isinstance(data.get("detail"), list)):
                    techs.add("FastAPI / Starlette (Python) or Django REST Framework")
                    error_hints.append("FastAPI/DRF `detail` error envelope")
                if {"statusCode", "message", "error"} <= keys:
                    techs.add("NestJS (Node.js / TypeScript)")
                    error_hints.append("NestJS standard `{statusCode, message, error}` envelope")
                if {"timestamp", "status", "error", "path"} <= keys:
                    techs.add("Spring Boot (Java / Kotlin)")
                    error_hints.append("Spring Boot Whitelabel JSON error envelope")
                if "errors" in keys and isinstance(data["errors"], list):
                    techs.add("GraphQL Server")
                    error_hints.append("GraphQL `errors[]` specification shape")
        except Exception:
            if re.search(r"(?i)whitelabel error page", body):
                techs.add("Spring Boot (Java)")
            elif re.search(r"(?i)werkzeug debugger|traceback \(most recent call last\)", body):
                techs.add("Flask / Werkzeug (Python)")

        api_hosts = [host] if any(k in host.lower() for k in ("api", "gql", "graphql", "gateway", "auth")) else []

        security_headers_present = {
            h: lower_headers[h]
            for h in (
                "strict-transport-security",
                "content-security-policy",
                "x-content-type-options",
                "x-frame-options",
                "referrer-policy",
                "permissions-policy",
                "cache-control",
                "access-control-allow-origin",
                "access-control-allow-credentials",
            )
            if h in lower_headers
        }
        missing_recommended = [
            h
            for h in (
                "strict-transport-security",
                "x-content-type-options",
                "content-security-policy",
            )
            if h not in lower_headers
        ]
        posture: Dict[str, Any] = {
            "status_code": status_code,
            "present_security_headers": security_headers_present,
            "missing_recommended_headers": missing_recommended,
        }
        if lower_headers.get("access-control-allow-origin"):
            posture["cors_origin_header"] = lower_headers["access-control-allow-origin"]
            posture["cors_credentials"] = lower_headers.get("access-control-allow-credentials", "")

        return FingerprintReport(
            target=url,
            discovered_hosts=[host] if host else [],
            api_candidate_hosts=api_hosts,
            detected_technologies=sorted(techs),
            auth_mechanisms=sorted(auths),
            error_shape_hints=sorted(error_hints),
            high_value_endpoints=[parsed.path] if parsed.path and parsed.path != "/" else [],
            security_posture=posture,
        )

    @classmethod
    def fetch_and_fingerprint(cls, url: str, timeout: float = 8.0) -> FingerprintReport:
        """Safely fetch live HTTP response headers & body (with Origin check) and fingerprint stack + posture."""
        norm_url = normalize_url(url)
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        test_origin = "https://untrusted-audit.example"
        req = urllib.request.Request(
            norm_url,
            headers={
                "User-Agent": "ViperClaw-Fingerprinter/2.0",
                "Accept": "application/json, text/html, */*",
                "Origin": test_origin,
            },
            method="GET",
        )
        status = 0
        resp_headers: Dict[str, str] = {}
        body = ""
        err_msg = ""
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ssl_ctx) as resp:
                status = resp.status
                resp_headers = {k: v for k, v in resp.headers.items()}
                body = resp.read(65536).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as he:
            status = he.code
            resp_headers = {k: v for k, v in he.headers.items()} if he.headers else {}
            body = he.read(32768).decode("utf-8", errors="replace") if he.fp else ""
        except Exception as exc:
            err_msg = str(exc)

        rep = cls.fingerprint_response(norm_url, resp_headers, body, status_code=status)
        if err_msg:
            rep.security_posture["connection_error"] = err_msg
        else:
            acao = rep.security_posture.get("cors_origin_header", "")
            acac = rep.security_posture.get("cors_credentials", "").lower() == "true"
            rep.security_posture["cors_origin_reflected"] = (acao == test_origin)
            rep.security_posture["cors_credentialed_reflection"] = (acao == test_origin and acac)
            rep.security_posture["body_preview"] = body[:240]
        return rep

    @classmethod
    def analyze_har(cls, har_path: str | Path, root_domain: str = "") -> FingerprintReport:
        path = Path(har_path)
        if not path.is_file():
            return FingerprintReport(target=root_domain or str(har_path))
        try:
            raw = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return FingerprintReport(target=root_domain or str(har_path))
        if not isinstance(raw, dict):
            return FingerprintReport(target=root_domain or str(har_path))
        log_obj = raw.get("log")
        if not isinstance(log_obj, dict):
            return FingerprintReport(target=root_domain or str(har_path))
        entries = log_obj.get("entries")
        if not isinstance(entries, list):
            entries = []

        hosts: Set[str] = set()
        api_hosts: Set[str] = set()
        techs: Set[str] = set()
        auths: Set[str] = set()
        error_hints: Set[str] = set()
        endpoints: Set[str] = set()

        for entry in entries:
            if not isinstance(entry, dict):
                continue
            req = entry.get("request") or {}
            resp = entry.get("response") or {}
            if not isinstance(req, dict) or not isinstance(resp, dict):
                continue
            url = str(req.get("url") or "")
            parsed = urlparse(url)
            host = parsed.netloc
            if not host:
                continue
            if root_domain and root_domain.lower() not in host.lower():
                continue

            hosts.add(host)
            if any(k in host.lower() or k in parsed.path.lower() for k in ("api", "graphql", "v1", "v2", "v3", "internal", "auth", "trpc")):
                api_hosts.add(host)
                endpoints.add(f"{req.get('method', 'GET')} {parsed.scheme}://{host}{parsed.path}")

            req_hdr_list = req.get("headers") if isinstance(req.get("headers"), list) else []
            req_headers = {str(h["name"]).lower(): str(h["value"]) for h in req_hdr_list if isinstance(h, dict) and "name" in h and "value" in h}
            if "authorization" in req_headers:
                val = req_headers["authorization"]
                scheme = val.split()[0] if val else "Bearer"
                auths.add(f"Authorization Header ({scheme})")
            for custom_key in ("x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token"):
                if custom_key in req_headers:
                    auths.add(f"Custom Header ({custom_key})")

            resp_hdr_list = resp.get("headers") if isinstance(resp.get("headers"), list) else []
            resp_headers = {str(h["name"]).lower(): str(h["value"]) for h in resp_hdr_list if isinstance(h, dict) and "name" in h and "value" in h}
            content_obj = resp.get("content") if isinstance(resp.get("content"), dict) else {}
            body_text = str(content_obj.get("text") or "")
            sub = cls.fingerprint_response(url, resp_headers, body_text, int(resp.get("status") or 200))
            techs.update(sub.detected_technologies)
            auths.update(sub.auth_mechanisms)
            error_hints.update(sub.error_shape_hints)

        return FingerprintReport(
            target=root_domain or str(har_path),
            discovered_hosts=sorted(hosts),
            api_candidate_hosts=sorted(api_hosts),
            detected_technologies=sorted(techs),
            auth_mechanisms=sorted(auths),
            error_shape_hints=sorted(error_hints),
            high_value_endpoints=sorted(endpoints)[:100],
        )
