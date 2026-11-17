---
name: viper-zero-trust-mtls-mesh
description: Zero-Trust Service Mesh, Istio/Linkerd mTLS & SPIFFE/SPIRE Auditor. Reviews PeerAuthentication STRICT mTLS, SPIFFE AuthorizationPolicy allowlists, and cert rotation.
---

# ViperClaw Skill 61: Zero-Trust Service Mesh, mTLS & SPIFFE/SPIRE Auditor (`viper-zero-trust-mtls-mesh`)

## 1. Standards & Open-Source Reference
- **Standards:** NIST SP 800-207 (Zero Trust Architecture), Istio Security Best Practices, CNCF SPIFFE/SPIRE Specification.
- **Focus:** Auditing Kubernetes service mesh manifests (`PeerAuthentication`, `AuthorizationPolicy`, `DestinationRule`) and internal mTLS configurations.

## 2. Rapid Discovery Patterns
- Search Kubernetes/Istio YAML files for `kind: PeerAuthentication`, `mode: PERMISSIVE`, `mode: DISABLE`, `kind: AuthorizationPolicy`, `spiffe://`.

## 3. Technical Audit Checklist
1. **Mesh-Wide `STRICT` Mutual TLS (`PeerAuthentication`):** Audit Istio `PeerAuthentication` resources in `istio-system` and workload namespaces; flag `mode: PERMISSIVE` or `mode: DISABLE` in production and enforce `mtls: { mode: STRICT }` so plaintext lateral movement is rejected.
2. **Default-Deny & SPIFFE Identity `AuthorizationPolicy`:** Deploy a namespace-wide default-deny `AuthorizationPolicy` (`spec: {}`) and grant access using explicit `from: [{ source: { principals: ["cluster.local/ns/prod/sa/checkout-sa"] } }]` combined with allowed HTTP methods and paths.
3. **Ingress Gateway Host & SNI Isolation:** Ensure Istio `Gateway` and `VirtualService` definitions bind to explicit hostnames (never `hosts: ["*"]` on production TLS gateways) and enforce `minProtocolVersion: TLSV1_2`.
4. **Egress Traffic Control (`REGISTRY_ONLY`):** Set `meshConfig.outboundTrafficPolicy.mode: REGISTRY_ONLY` and require explicit `ServiceEntry` definitions for approved external APIs so compromised pods cannot connect to arbitrary external hosts.
5. **Short-Lived Workload SVID Rotation:** Confirm SPIFFE/Istio workload X.509 certificates use short TTLs (<= 24 hours) with automated SDS rotation and never mount static root CA private keys into application pods.

## 4. Vulnerable vs. Hardened Pattern
```yaml
# ❌ VULNERABLE: Permissive mTLS & allows any pod in cluster to call payments service
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: prod
spec:
  mtls:
    mode: PERMISSIVE

# ✅ HARDENED: Strict mTLS + SPIFFE principal allowlist scoped to specific POST route
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: prod
spec:
  mtls:
    mode: STRICT
---
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: payments-allow-checkout
  namespace: prod
spec:
  selector:
    matchLabels:
      app: payments-service
  action: ALLOW
  rules:
    - from:
        - source:
            principals: ["cluster.local/ns/prod/sa/checkout-service"]
      to:
        - operation:
            methods: ["POST"]
            paths: ["/v1/charge"]
```
