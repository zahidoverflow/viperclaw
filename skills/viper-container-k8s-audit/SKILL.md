---
name: viper-container-k8s-audit
description: Docker Container & Kubernetes Manifest Security Auditor (modeled on Trivy, Kubescape & CIS Benchmarks). Reviews Dockerfiles, PodSecurityContexts, RBAC roles, and network policies.
---

# ViperClaw Skill 18: Docker & Kubernetes Security Auditor (`viper-container-k8s-audit`)

## Overview
Audits `Dockerfile`, `docker-compose.yml`, Helm charts, and Kubernetes YAML manifests against CIS Docker/Kubernetes Benchmarks and Pod Security Standards (Restricted profile).

## Audit Checklist
1. **Dockerfile Hardening:** Use minimal/distroless base images pinned by digest, run as a non-root `USER`, never pass secrets via `ARG`/`ENV`, and use multi-stage builds.
2. **Kubernetes Pod Security Context:** Enforce `runAsNonRoot: true`, `allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities.drop: ["ALL"]`, and `automountServiceAccountToken: false`.
3. **RBAC & Network Segmentation:** Audit `ClusterRole` bindings for wildcard verbs/resources (`*`) and ensure `NetworkPolicy` manifests restrict pod-to-pod and egress traffic.
