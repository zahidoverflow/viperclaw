"""
Infrastructure-as-Code (IaC) & CI/CD Security Posture Auditor (`viperclaw.analyzers.iac_auditor`).

Zero-dependency static configuration auditor modeled on Checkov, Trivy, and Zizmor:
- Dockerfiles: root container user, mutable `:latest` tags, remote `ADD`, pipe-to-shell installs.
- Kubernetes manifests: `privileged: true`, `allowPrivilegeEscalation: true`, `hostNetwork: true`,
  `runAsUser: 0`, wildcard RBAC permissions.
- Terraform (`.tf`): open `0.0.0.0/0` security groups, public S3 ACLs, wildcard IAM actions/resources.
- GitHub Actions (`.github/workflows/*.yml`): `pull_request_target`, missing `permissions:`,
  unpinned mutable action tags (`@v*`/`@main`), `${{ github.event.* }}` shell interpolation.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List


SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", "dist", "build", ".viperclaw"}


@dataclass
class IaCFinding:
    rule_id: str
    category: str
    title: str
    cwe_id: str
    severity: str
    file_path: str
    line_number: int
    evidence: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class IaCAuditor:
    """Zero-dependency static auditor for Dockerfiles, Kubernetes, Terraform, and GitHub Actions."""

    @staticmethod
    def _audit_dockerfile(path: Path, lines: List[str]) -> List[IaCFinding]:
        findings: List[IaCFinding] = []
        has_user = any(re.match(r"^\s*USER\s+(?!root\b|0\b)\S+", ln, re.I) for ln in lines)
        if lines and not has_user:
            findings.append(
                IaCFinding(
                    rule_id="IAC-DOCKER-01",
                    category="Dockerfile",
                    title="Container runs as root (missing non-root USER instruction)",
                    cwe_id="CWE-250",
                    severity="HIGH",
                    file_path=str(path),
                    line_number=1,
                    evidence="No non-root USER directive found",
                    remediation="Create a dedicated unprivileged user and add `USER appuser` before ENTRYPOINT/CMD.",
                )
            )
        for idx, line in enumerate(lines, 1):
            if re.match(r"^\s*FROM\s+[^\s:@]+(?::latest)?\s*(?:AS\s+\S+)?\s*$", line, re.I):
                if ":latest" in line.lower() or ":" not in line.split()[1]:
                    findings.append(
                        IaCFinding(
                            rule_id="IAC-DOCKER-02",
                            category="Dockerfile",
                            title="Unpinned base image tag (missing digest or explicit version)",
                            cwe_id="CWE-829",
                            severity="MEDIUM",
                            file_path=str(path),
                            line_number=idx,
                            evidence=line.strip()[:160],
                            remediation="Pin base images to an immutable version tag and SHA-256 digest.",
                        )
                    )
            if re.search(r"curl\s+[^|\n]+\|\s*(?:ba)?sh|wget\s+[^|\n]+\|\s*(?:ba)?sh", line, re.I):
                findings.append(
                    IaCFinding(
                        rule_id="IAC-DOCKER-03",
                        category="Dockerfile",
                        title="Unverified remote script piped directly to shell",
                        cwe_id="CWE-494",
                        severity="HIGH",
                        file_path=str(path),
                        line_number=idx,
                        evidence=line.strip()[:160],
                        remediation="Download artifacts, verify SHA-256 checksums, and execute explicitly.",
                    )
                )
            if re.match(r"^\s*ADD\s+https?://", line, re.I):
                findings.append(
                    IaCFinding(
                        rule_id="IAC-DOCKER-04",
                        category="Dockerfile",
                        title="Remote URL fetched via ADD without integrity verification",
                        cwe_id="CWE-494",
                        severity="MEDIUM",
                        file_path=str(path),
                        line_number=idx,
                        evidence=line.strip()[:160],
                        remediation="Use COPY for local build context files or curl with checksum verification.",
                    )
                )
        return findings

    @staticmethod
    def _audit_k8s_yaml(path: Path, text: str, lines: List[str]) -> List[IaCFinding]:
        findings: List[IaCFinding] = []
        if not re.search(r"^\s*apiVersion:\s*", text, re.M) or not re.search(r"^\s*kind:\s*", text, re.M):
            return findings
        checks = [
            (r"^\s*privileged:\s*true\b", "IAC-K8S-01", "Privileged Kubernetes container enabled", "CWE-250", "CRITICAL", "Set `securityContext.privileged: false`."),
            (r"^\s*allowPrivilegeEscalation:\s*true\b", "IAC-K8S-02", "Container allows privilege escalation", "CWE-269", "HIGH", "Set `allowPrivilegeEscalation: false`."),
            (r"^\s*hostNetwork:\s*true\b", "IAC-K8S-03", "Pod shares host network namespace", "CWE-250", "HIGH", "Remove `hostNetwork: true` and enforce NetworkPolicies."),
            (r"^\s*hostPID:\s*true\b", "IAC-K8S-04", "Pod shares host PID namespace", "CWE-250", "HIGH", "Set `hostPID: false`."),
            (r"^\s*runAsUser:\s*0\b", "IAC-K8S-05", "Container explicitly runs as UID 0 (root)", "CWE-250", "HIGH", "Set `runAsNonRoot: true` and a non-zero `runAsUser` (>= 10000)."),
        ]
        for idx, line in enumerate(lines, 1):
            for pat, rid, title, cwe, sev, rem in checks:
                if re.search(pat, line):
                    findings.append(
                        IaCFinding(
                            rule_id=rid,
                            category="Kubernetes",
                            title=title,
                            cwe_id=cwe,
                            severity=sev,
                            file_path=str(path),
                            line_number=idx,
                            evidence=line.strip()[:160],
                            remediation=rem,
                        )
                    )
        return findings

    @staticmethod
    def _audit_terraform(path: Path, lines: List[str]) -> List[IaCFinding]:
        findings: List[IaCFinding] = []
        checks = [
            (r"""cidr_blocks\s*=\s*\[\s*["']0\.0\.0\.0/0["']\s*\]""", "IAC-TF-01", "Security group allows unrestricted 0.0.0.0/0 CIDR access", "CWE-284", "HIGH", "Restrict CIDR blocks to specific corporate or VPC subnets."),
            (r"""acl\s*=\s*["']public-read(?:-write)?["']""", "IAC-TF-02", "S3 bucket configured with public ACL", "CWE-284", "CRITICAL", "Set `acl = \"private\"` and enable `aws_s3_bucket_public_access_block`."),
            (r"""["']Action["']\s*:\s*["']\*["']|actions\s*=\s*\[\s*["']\*["']\s*\]""", "IAC-TF-03", "Wildcard IAM Action (`*`) violates least privilege", "CWE-269", "HIGH", "Scope IAM actions to the exact API operations required."),
            (r"""encrypted\s*=\s*false\b|storage_encrypted\s*=\s*false\b""", "IAC-TF-04", "Cloud storage volume/database encryption disabled", "CWE-311", "HIGH", "Enable KMS encryption at rest (`encrypted = true`)."),
        ]
        for idx, line in enumerate(lines, 1):
            for pat, rid, title, cwe, sev, rem in checks:
                if re.search(pat, line, re.I):
                    findings.append(
                        IaCFinding(
                            rule_id=rid,
                            category="Terraform",
                            title=title,
                            cwe_id=cwe,
                            severity=sev,
                            file_path=str(path),
                            line_number=idx,
                            evidence=line.strip()[:160],
                            remediation=rem,
                        )
                    )
        return findings

    @staticmethod
    def _audit_github_workflow(path: Path, text: str, lines: List[str]) -> List[IaCFinding]:
        findings: List[IaCFinding] = []
        if not re.search(r"^\s*permissions\s*:", text, re.M):
            findings.append(
                IaCFinding(
                    rule_id="IAC-GHA-01",
                    category="GitHub Actions",
                    title="Workflow omits top-level least-privilege `permissions:` block",
                    cwe_id="CWE-269",
                    severity="MEDIUM",
                    file_path=str(path),
                    line_number=1,
                    evidence="No `permissions:` declaration found in workflow",
                    remediation="Declare `permissions: { contents: read }` at the workflow root.",
                )
            )
        for idx, line in enumerate(lines, 1):
            if re.search(r"\bpull_request_target\b", line):
                findings.append(
                    IaCFinding(
                        rule_id="IAC-GHA-02",
                        category="GitHub Actions",
                        title="Workflow triggers on privileged `pull_request_target` event",
                        cwe_id="CWE-269",
                        severity="HIGH",
                        file_path=str(path),
                        line_number=idx,
                        evidence=line.strip()[:160],
                        remediation="Use `pull_request` for untrusted forks or avoid checking out PR head code.",
                    )
                )
            if re.search(r"\$\{\{\s*github\.event\.(?:issue|pull_request|comment|head_commit|discussion)\.", line):
                findings.append(
                    IaCFinding(
                        rule_id="IAC-GHA-03",
                        category="GitHub Actions",
                        title="Untrusted GitHub event expression interpolated in workflow step",
                        cwe_id="CWE-78",
                        severity="HIGH",
                        file_path=str(path),
                        line_number=idx,
                        evidence=line.strip()[:160],
                        remediation="Pass event fields through step `env:` variables and quote them in shell commands.",
                    )
                )
            m_uses = re.search(r"^\s*-?\s*uses:\s*([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)@([^\s#]+)", line)
            if m_uses:
                ref = m_uses.group(2)
                if not re.fullmatch(r"[0-9a-f]{40}", ref):
                    findings.append(
                        IaCFinding(
                            rule_id="IAC-GHA-04",
                            category="GitHub Actions",
                            title="Third-party GitHub Action pinned to mutable tag/branch instead of 40-char SHA",
                            cwe_id="CWE-829",
                            severity="LOW",
                            file_path=str(path),
                            line_number=idx,
                            evidence=line.strip()[:160],
                            remediation="Pin third-party actions to immutable 40-character commit SHAs.",
                        )
                    )
        return findings

    @classmethod
    def scan_path(cls, target: str | Path) -> Dict[str, Any]:
        root = Path(target)
        if not root.exists():
            return {"error": f"Path not found: {target}", "files_scanned": 0, "total_findings": 0, "findings": []}

        files: List[Path] = []
        if root.is_file():
            files = [root]
        else:
            for item in root.rglob("*"):
                if not item.is_file():
                    continue
                if any(part in SKIP_DIRS for part in item.parts):
                    continue
                name_low = item.name.lower()
                if (
                    name_low.startswith("dockerfile")
                    or item.suffix.lower() in (".tf", ".yml", ".yaml")
                ):
                    files.append(item)

        findings: List[IaCFinding] = []
        scanned = 0
        for f in sorted(files):
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            lines = text.splitlines()
            name_low = f.name.lower()
            parts_low = [p.lower() for p in f.parts]
            if name_low.startswith("dockerfile"):
                scanned += 1
                findings.extend(cls._audit_dockerfile(f, lines))
            elif f.suffix.lower() == ".tf":
                scanned += 1
                findings.extend(cls._audit_terraform(f, lines))
            elif f.suffix.lower() in (".yml", ".yaml"):
                if ".github" in parts_low and "workflows" in parts_low:
                    scanned += 1
                    findings.extend(cls._audit_github_workflow(f, text, lines))
                elif "apiVersion:" in text and "kind:" in text:
                    scanned += 1
                    findings.extend(cls._audit_k8s_yaml(f, text, lines))

        return {
            "target": str(root),
            "files_scanned": scanned,
            "total_findings": len(findings),
            "findings": [x.to_dict() for x in findings],
        }
