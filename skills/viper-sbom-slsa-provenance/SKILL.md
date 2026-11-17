---
name: viper-sbom-slsa-provenance
description: SLSA Build Provenance, Sigstore Cosign & Artifact Integrity Auditor. Reviews SLSA Level 3 provenance attestations, Cosign keyless OIDC signing, and CycloneDX/SPDX SBOMs.
---

# ViperClaw Skill 59: SLSA Build Provenance, Sigstore Cosign & SBOM Auditor (`viper-sbom-slsa-provenance`)

## 1. Standards & Open-Source Reference
- **Standards:** SLSA v1.0 (Supply-chain Levels for Software Artifacts), Sigstore `cosign`, PyPI Trusted Publishers (OIDC), CycloneDX / SPDX SBOM.
- **Focus:** Auditing release pipelines, container image signing, package publishing, and build provenance verification.

## 2. Rapid Discovery Patterns
- Search release workflows for `slsa-framework/slsa-github-generator`, `actions/attest-build-provenance`, `sigstore/cosign-installer`, `id-token: write`.

## 3. Technical Audit Checklist
1. **Keyless OIDC Trusted Publishing (PyPI / npm / Crates):** Replace long-lived `PYPI_API_TOKEN` or `NPM_TOKEN` secrets in release workflows with OIDC Trusted Publishing (`id-token: write` + `npm publish --provenance` or `pypa/gh-action-pypi-publish`).
2. **SLSA Build Provenance Attestation:** Generate cryptographic build provenance attestations (`actions/attest-build-provenance` or `slsa-github-generator`) in isolated, ephemeral build runners so consumers can verify the artifact was built from the exact commit SHA.
3. **Container Image Signing & Digest Pinning (`cosign`):** Sign published container images by `@sha256:...` digest (never mutable tags like `:latest`) using Sigstore `cosign sign --yes image@sha256:...`, and enforce signature verification via Kyverno / Sigstore Policy Controller in Kubernetes.
4. **Automated SBOM Generation & Attestation:** Emit a CycloneDX or SPDX Software Bill of Materials (`syft` / `cyclonedx-bom`) alongside every release artifact and attach it via `cosign attach sbom`.
5. **Hermetic & Reproducible Build Hygiene:** Ensure release builds run with `--locked` / `--frozen-lockfile`, set `SOURCE_DATE_EPOCH`, and do not fetch unverified remote scripts (`curl ... | sh`) during compilation.

## 4. Vulnerable vs. Hardened Pattern
```yaml
# ❌ VULNERABLE: Publishes package using static long-lived secret token without provenance
- run: twine upload dist/* -u __token__ -p ${{ secrets.PYPI_TOKEN }}

# ✅ HARDENED: Keyless OIDC Trusted Publisher with GitHub Artifact Provenance Attestation
permissions:
  contents: read
  id-token: write
  attestations: write
steps:
  - uses: actions/attest-build-provenance@v2
    with:
      subject-path: "dist/*"
  - uses: pypa/gh-action-pypi-publish@release/v1
```
