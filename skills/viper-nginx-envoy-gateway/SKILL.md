---
name: viper-nginx-envoy-gateway
description: Nginx, Envoy, Traefik & API Gateway Security Auditor (modeled on Gixy & OWASP Reverse Proxy). Reviews Nginx alias traversal, header drop, CRLF splitting, and XFF trust.
---

# ViperClaw Skill 51: Nginx, Envoy & API Gateway Security Auditor (`viper-nginx-envoy-gateway`)

## 1. Standards & Open-Source Reference
- **Standards:** `yandex/gixy` (Nginx Configuration Static Analyzer), Envoy Security Best Practices, OWASP Reverse Proxy Guidelines.
- **Focus:** Auditing `nginx.conf`, Envoy YAML filters, Traefik ingress rules, and Kong/APISIX gateway routes.

## 2. Rapid Discovery Patterns
- **Nginx:** `alias `, `return 302 $uri`, `add_header `, `proxy_pass http://$host`, `set_real_ip_from 0.0.0.0/0`.
- **Envoy:** `use_remote_address: false`, `xff_num_trusted_hops`, `ext_authz`, `failure_mode_allow: true`.

## 3. Technical Audit Checklist
1. **Nginx `location` + `alias` Off-By-Slash Path Traversal (Gixy):** If a `location /static` block does **not** end with a trailing slash `/` while `alias /var/www/static/;` **does**, requesting `/static../app/settings.py` traverses into `/var/www/app/settings.py`! Always ensure both `location` and `alias` end with `/`.
2. **Nginx `add_header` Inheritance Drop:** In Nginx, adding *any* `add_header` inside a nested `location` block silently drops **all** `add_header` directives (like HSTS, CSP, `X-Frame-Options`) defined in the parent `server` or `http` block! Repeat security headers via an `include security_headers.conf;`.
3. **CRLF Header Injection via Unencoded `$uri` / `$request_uri`:** In Nginx redirects or `proxy_set_header`, `$uri` is URL-decoded and can contain `
` (CRLF response splitting). Use `$request_uri` instead of `$uri` in `return 301 https://$host$request_uri;`.
4. **Envoy / Nginx `X-Forwarded-For` Spoofing Defense:** Never set `set_real_ip_from 0.0.0.0/0` in Nginx or `use_remote_address: false` on edge Envoy listeners; configure exact trusted proxy CIDRs and `xff_num_trusted_hops`.
5. **External Auth (`ext_authz`) Fail-Closed Enforcement:** In Envoy `envoy.filters.http.ext_authz`, ensure `failure_mode_allow: false` so an auth-service timeout never fails open.

## 4. Vulnerable vs. Hardened Pattern
```nginx
# ❌ VULNERABLE: Off-by-slash alias traversal & decoded $uri CRLF injection
location /assets {
    alias /var/www/public/assets/;
}
location /old {
    return 301 https://$host$uri;
}

# ✅ HARDENED: Matching trailing slashes & raw $request_uri
location /assets/ {
    alias /var/www/public/assets/;
}
location /old {
    return 301 https://$host$request_uri;
}
```
