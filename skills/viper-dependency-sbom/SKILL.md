---
name: viper-dependency-sbom
description: Software Supply Chain, Lockfile Integrity & Dependency Vulnerability Auditor (modeled on OSV-Scanner, Pip-Audit & Dependabot). Reviews manifests, lockfiles, and namespace confusion risks.
---

# ViperClaw Skill 16: Supply Chain, SBOM & Dependency Auditor (`viper-dependency-sbom`)

## Overview
Audits `pyproject.toml`, `requirements.txt`, `package-lock.json`, `pnpm-lock.yaml`, `go.sum`, and `Cargo.lock` for vulnerable dependencies, unpinned versions, and private registry namespace confusion.

## Audit Checklist
1. **Lockfile Pinning & Hash Integrity:** Ensure production builds use deterministic lockfiles (`npm ci`, `pip install --require-hashes`, `cargo build --locked`) rather than floating version ranges.
2. **Private Scope & Registry Configuration:** Verify `.npmrc`, `pip.conf`, and `.cargo/config.toml` explicitly bind internal `@scopes` to private registries to prevent dependency confusion.
3. **Known CVE & Lifecycle Triage:** Cross-reference dependency versions against OSV/GitHub Advisory databases and prioritize upgrades for reachable vulnerable functions.
