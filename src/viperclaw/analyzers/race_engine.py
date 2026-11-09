"""
Barrier-Synchronized Race Condition & TOCTOU Burst Engine (`viperclaw.analyzers.race_engine`).

Uses pre-connected `http.client` socket workers synchronized via `threading.Barrier`
so all parallel requests release their final payload bytes at the exact same
microsecond—proving single-use token reuse, coupon/balance double-spend, and
rate-limit overruns with zero external dependencies.
"""

from __future__ import annotations

import hashlib
import http.client
import ssl
import threading
import time
import urllib.parse
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class RaceWorkerResult:
    worker_id: int
    status_code: int
    elapsed_ms: float
    release_offset_ms: float
    body_length: int
    body_sha256: str
    body_preview: str
    headers: Dict[str, str] = field(default_factory=dict)
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "worker_id": self.worker_id,
            "status_code": self.status_code,
            "elapsed_ms": round(self.elapsed_ms, 3),
            "release_offset_ms": round(self.release_offset_ms, 3),
            "body_length": self.body_length,
            "body_sha256": self.body_sha256,
            "body_preview": self.body_preview,
            "headers": self.headers,
            "error": self.error,
        }


@dataclass
class RaceBurstReport:
    target_url: str
    method: str
    concurrency: int
    release_jitter_ms: float
    status_distribution: Dict[str, int]
    success_count: int
    unique_body_hashes: int
    race_window_proven: bool
    verdict: str
    workers: List[RaceWorkerResult] = field(default_factory=list)
    request_receipt: str = ""
    response_receipt: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_url": self.target_url,
            "method": self.method,
            "concurrency": self.concurrency,
            "release_jitter_ms": round(self.release_jitter_ms, 3),
            "status_distribution": self.status_distribution,
            "success_count": self.success_count,
            "unique_body_hashes": self.unique_body_hashes,
            "race_window_proven": self.race_window_proven,
            "verdict": self.verdict,
            "request_receipt": self.request_receipt,
            "response_receipt": self.response_receipt,
            "workers": [w.to_dict() for w in self.workers],
        }


class RaceEngine:
    """Pre-warmed barrier-synchronized HTTP race condition tester."""

    @staticmethod
    def execute_burst(
        url: str,
        method: str = "POST",
        headers: Dict[str, str] | None = None,
        body: str = "",
        concurrency: int = 15,
        timeout: float = 8.0,
        success_indicator: str = "",
        max_expected_successes: int = 1,
    ) -> RaceBurstReport:
        parsed = urllib.parse.urlsplit(url)
        scheme = (parsed.scheme or "http").lower()
        host = parsed.hostname or "127.0.0.1"
        port = parsed.port or (443 if scheme == "https" else 80)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"

        concurrency = max(2, min(int(concurrency), 64))
        method_up = method.upper()
        body_bytes = body.encode("utf-8") if isinstance(body, str) else b""

        req_headers: Dict[str, str] = {
            "Host": f"{host}:{port}" if parsed.port else host,
            "User-Agent": "ViperClaw-RaceEngine/2.0",
            "Accept": "*/*",
            "Connection": "keep-alive",
        }
        if body_bytes and "Content-Type" not in (headers or {}) and "content-type" not in (headers or {}):
            req_headers["Content-Type"] = "application/x-www-form-urlencoded"
        if body_bytes:
            req_headers["Content-Length"] = str(len(body_bytes))
        if headers:
            req_headers.update(headers)

        barrier = threading.Barrier(concurrency, timeout=timeout)
        results: List[RaceWorkerResult | None] = [None] * concurrency
        release_times: List[float] = [0.0] * concurrency

        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

        def _worker(idx: int) -> None:
            conn: http.client.HTTPConnection | None = None
            try:
                if scheme == "https":
                    conn = http.client.HTTPSConnection(host, port, timeout=timeout, context=ssl_ctx)
                else:
                    conn = http.client.HTTPConnection(host, port, timeout=timeout)
                conn.connect()

                # Send request line and headers before waiting at the barrier if body is present,
                # or wait at the barrier right before flushing the request over the pre-connected socket.
                conn.putrequest(method_up, path, skip_host=True, skip_accept_encoding=True)
                for hk, hv in req_headers.items():
                    conn.putheader(hk, hv)

                if body_bytes and len(body_bytes) > 1:
                    conn.endheaders(body_bytes[:-1])
                    final_chunk = body_bytes[-1:]
                    try:
                        barrier.wait()
                    except threading.BrokenBarrierError:
                        pass
                    t_release = time.perf_counter()
                    release_times[idx] = t_release
                    conn.send(final_chunk)
                else:
                    try:
                        barrier.wait()
                    except threading.BrokenBarrierError:
                        pass
                    t_release = time.perf_counter()
                    release_times[idx] = t_release
                    conn.endheaders(body_bytes if body_bytes else None)

                resp = conn.getresponse()
                raw_data = resp.read(32768)
                t_done = time.perf_counter()
                text_body = raw_data.decode("utf-8", errors="replace")
                resp_hdrs = {k.lower(): v for k, v in resp.getheaders()}
                results[idx] = RaceWorkerResult(
                    worker_id=idx + 1,
                    status_code=resp.status,
                    elapsed_ms=(t_done - t_release) * 1000.0,
                    release_offset_ms=0.0,
                    body_length=len(raw_data),
                    body_sha256=hashlib.sha256(raw_data).hexdigest()[:16],
                    body_preview=text_body[:240],
                    headers=resp_hdrs,
                )
            except Exception as exc:
                results[idx] = RaceWorkerResult(
                    worker_id=idx + 1,
                    status_code=0,
                    elapsed_ms=0.0,
                    release_offset_ms=0.0,
                    body_length=0,
                    body_sha256="",
                    body_preview="",
                    error=str(exc),
                )
            finally:
                if conn is not None:
                    try:
                        conn.close()
                    except Exception:
                        pass

        threads = [threading.Thread(target=_worker, args=(i,), daemon=True) for i in range(concurrency)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=timeout + 2.0)

        valid_times = [t for t in release_times if t > 0.0]
        min_time = min(valid_times) if valid_times else 0.0
        max_time = max(valid_times) if valid_times else 0.0
        jitter_ms = (max_time - min_time) * 1000.0 if valid_times else 0.0

        final_workers: List[RaceWorkerResult] = []
        status_dist: Dict[str, int] = {}
        body_hashes: set[str] = set()
        success_count = 0

        for i, w in enumerate(results):
            if w is None:
                continue
            if release_times[i] > 0.0 and min_time > 0.0:
                w.release_offset_ms = (release_times[i] - min_time) * 1000.0
            final_workers.append(w)
            if w.status_code > 0:
                sk = str(w.status_code)
                status_dist[sk] = status_dist.get(sk, 0) + 1
                if w.body_sha256:
                    body_hashes.add(w.body_sha256)
                is_2xx = 200 <= w.status_code < 300
                if success_indicator:
                    if success_indicator.lower() in w.body_preview.lower() and is_2xx:
                        success_count += 1
                elif is_2xx:
                    success_count += 1

        race_proven = success_count > max_expected_successes
        if race_proven:
            verdict = (
                f"TOCTOU Race Window Proven: {success_count}/{concurrency} concurrent requests succeeded "
                f"(expected <= {max_expected_successes}) with {jitter_ms:.2f}ms release jitter."
            )
        else:
            verdict = (
                f"No overrun observed: {success_count}/{concurrency} succeeded "
                f"(status distribution: {status_dist}, release jitter: {jitter_ms:.2f}ms)."
            )

        hdr_str = "\n".join(f"{k}: {v}" for k, v in req_headers.items())
        req_receipt = (
            f"{method_up} {path} HTTP/1.1 [x{concurrency} Barrier-Synchronized Burst]\n"
            f"{hdr_str}\n\n{body}"
        ).strip()

        sample_lines = [
            f"HTTP/1.1 {w.status_code} [Worker #{w.worker_id} | +{w.release_offset_ms:.2f}ms | {w.elapsed_ms:.1f}ms] -> {w.body_preview[:120]}"
            for w in final_workers[:8]
        ]
        resp_receipt = (
            f"HTTP/1.1 200 Race-Burst-Summary (Jitter: {jitter_ms:.2f}ms, Successes: {success_count}/{concurrency})\n"
            + "\n".join(sample_lines)
        )

        return RaceBurstReport(
            target_url=url,
            method=method_up,
            concurrency=concurrency,
            release_jitter_ms=jitter_ms,
            status_distribution=status_dist,
            success_count=success_count,
            unique_body_hashes=len(body_hashes),
            race_window_proven=race_proven,
            verdict=verdict,
            workers=final_workers,
            request_receipt=req_receipt,
            response_receipt=resp_receipt,
        )
