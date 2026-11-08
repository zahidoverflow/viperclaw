---
name: viper-proxy-fingerprint
description: HTTP Stack & Proxy Traffic Fingerprinter. Discovers sibling API hosts, backend frameworks, error envelope shapes, auth mechanisms, and WAF soft-block traps from HAR captures or HTTP headers.
---

# ViperClaw HTTP & Proxy Fingerprinter (`viper-proxy-fingerprint`)

## Methodology
Before firing payloads, fingerprint the exact backend parser, framework error envelope, and upstream reverse-proxy / WAF layer.

## Heuristic Matrix

| Signal Source | Indicator | Inferred Stack & Next Move |
| :--- | :--- | :--- |
| **JSON Error Shape** | `{"detail": "..."}` or `{"detail": [{"loc": ...}]}` | **FastAPI / Starlette / DRF (Python)** — test type-confusion arrays, SSTI, and Pydantic mass assignment. |
| **JSON Error Shape** | `{"statusCode": 400, "message": "...", "error": "Bad Request"}` | **NestJS (Node.js)** — test prototype pollution, guard bypass, and GraphQL resolver authz gaps. |
| **JSON Error Shape** | `{"timestamp": ..., "status": 500, "error": "...", "path": "..."}` | **Spring Boot (Java)** — test Actuator exposure, SpEL injection, and path traversal matrix parameters (`;jsessionid=`). |
| **Cookie Name** | `laravel_session` / `XSRF-TOKEN` | **Laravel (PHP)** — test mass assignment, signed URL tampering, and PHP type juggling. |
| **Soft-200 Trap** | HTTP `200 OK` with tiny body or Challenge HTML | **WAF Soft-Block** — run `viper_diff_oracle` to avoid false-positive scanner hits. |

## Running the Fingerprinter
```bash
viperclaw fingerprint ./traffic.har --domain target.tld
```
