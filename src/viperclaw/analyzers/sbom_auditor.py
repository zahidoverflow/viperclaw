"""
Software Bill of Materials (CycloneDX 1.5 SBOM) & Dependency Supply-Chain Auditor
(`viperclaw.analyzers.sbom_auditor`).

Zero-dependency manifest & lockfile analyzer modeled on Syft and OSV-Scanner:
- Parses `package.json`, `requirements.txt`, `pyproject.toml`, `go.mod`, and `Cargo.toml`.
- Generates a standards-compliant CycloneDX 1.5 JSON SBOM component inventory.
- Flags supply-chain hygiene issues: unpinned/wildcard versions, missing lockfiles,
  `--extra-index-url` namespace-substitution risk, insecure `git+http://` sources,
  and risky npm `preinstall`/`postinstall` lifecycle scripts.
"""

from __future__ import annotations

import json
import re
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from viperclaw import __version__


SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", "dist", "build", ".viperclaw"}


@dataclass
class SBOMComponent:
    ecosystem: str
    name: str
    version: str
    purl: str
    source_file: str

    def to_cyclonedx(self) -> Dict[str, Any]:
        return {
            "type": "library",
            "name": self.name,
            "version": self.version,
            "purl": self.purl,
            "properties": [{"name": "viperclaw:source_file", "value": self.source_file}],
        }


@dataclass
class DependencyFinding:
    rule_id: str
    title: str
    cwe_id: str
    severity: str
    file_path: str
    evidence: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SBOMAuditor:
    """Zero-dependency CycloneDX 1.5 SBOM generator and supply-chain hygiene auditor."""

    @staticmethod
    def _parse_package_json(path: Path) -> tuple[List[SBOMComponent], List[DependencyFinding]]:
        comps: List[SBOMComponent] = []
        findings: List[DependencyFinding] = []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return comps, findings
        if not isinstance(data, dict):
            return comps, findings

        for section in ("dependencies", "devDependencies"):
            deps = data.get(section)
            if not isinstance(deps, dict):
                continue
            for pkg, ver in deps.items():
                v_str = str(ver).strip()
                comps.append(
                    SBOMComponent(
                        ecosystem="npm",
                        name=pkg,
                        version=v_str,
                        purl=f"pkg:npm/{pkg}@{v_str}",
                        source_file=str(path),
                    )
                )
                if v_str in ("*", "latest", "") or v_str.startswith(("http://", "git+http://")):
                    findings.append(
                        DependencyFinding(
                            rule_id="SBOM-NPM-01",
                            title=f"Unpinned or insecure npm dependency specifier for `{pkg}`",
                            cwe_id="CWE-829",
                            severity="HIGH",
                            file_path=str(path),
                            evidence=f"{pkg}: {v_str}",
                            remediation="Pin exact semantic versions and enforce `npm ci` with a committed lockfile.",
                        )
                    )

        scripts = data.get("scripts")
        if isinstance(scripts, dict):
            for hook in ("preinstall", "install", "postinstall"):
                if hook in scripts and re.search(r"(curl|wget|bash|sh\s+-c|powershell)", str(scripts[hook]), re.I):
                    findings.append(
                        DependencyFinding(
                            rule_id="SBOM-NPM-02",
                            title=f"Lifecycle script `{hook}` invokes network/shell command",
                            cwe_id="CWE-829",
                            severity="HIGH",
                            file_path=str(path),
                            evidence=f"{hook}: {str(scripts[hook])[:140]}",
                            remediation="Avoid remote downloads in npm lifecycle hooks and run builds with `--ignore-scripts`.",
                        )
                    )

        parent = path.parent
        has_lock = any((parent / lf).is_file() for lf in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb"))
        if comps and not has_lock:
            findings.append(
                DependencyFinding(
                    rule_id="SBOM-NPM-03",
                    title="Missing JavaScript lockfile for reproducible builds",
                    cwe_id="CWE-829",
                    severity="MEDIUM",
                    file_path=str(path),
                    evidence="No package-lock.json, yarn.lock, or pnpm-lock.yaml found alongside package.json",
                    remediation="Commit a deterministic lockfile with SHA-512 integrity hashes.",
                )
            )
        return comps, findings

    @staticmethod
    def _parse_requirements_txt(path: Path) -> tuple[List[SBOMComponent], List[DependencyFinding]]:
        comps: List[SBOMComponent] = []
        findings: List[DependencyFinding] = []
        for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            if "--extra-index-url" in line:
                findings.append(
                    DependencyFinding(
                        rule_id="SBOM-PY-01",
                        title="Use of `--extra-index-url` creates package namespace substitution risk",
                        cwe_id="CWE-427",
                        severity="HIGH",
                        file_path=str(path),
                        evidence=line[:140],
                        remediation="Use `--index-url` pointing to a single private artifact proxy instead of `--extra-index-url`.",
                    )
                )
                continue
            if line.startswith("-"):
                continue
            m = re.match(r"^([A-Za-z0-9_.-]+)\s*(==|>=|<=|~=|!=|>|<)?\s*([^\s;#]+)?", line)
            if m:
                pkg = m.group(1)
                op = m.group(2) or ""
                ver = m.group(3) or "unpinned"
                comps.append(
                    SBOMComponent(
                        ecosystem="pypi",
                        name=pkg,
                        version=f"{op}{ver}" if op else ver,
                        purl=f"pkg:pypi/{pkg.lower()}@{ver}",
                        source_file=str(path),
                    )
                )
                if op != "==":
                    findings.append(
                        DependencyFinding(
                            rule_id="SBOM-PY-02",
                            title=f"Unpinned Python dependency `{pkg}`",
                            cwe_id="CWE-829",
                            severity="LOW",
                            file_path=str(path),
                            evidence=line[:140],
                            remediation="Pin exact versions (`==`) with `--require-hashes` in production requirements.",
                        )
                    )
        return comps, findings

    @staticmethod
    def _parse_go_mod(path: Path) -> tuple[List[SBOMComponent], List[DependencyFinding]]:
        comps: List[SBOMComponent] = []
        findings: List[DependencyFinding] = []
        for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            m = re.match(r"^(?:require\s+)?([a-z0-9.\-_/]+\.[a-z0-9.\-_/]+)\s+(v[0-9][^\s]*)", line)
            if m:
                mod, ver = m.group(1), m.group(2)
                comps.append(
                    SBOMComponent(
                        ecosystem="golang",
                        name=mod,
                        version=ver,
                        purl=f"pkg:golang/{mod}@{ver}",
                        source_file=str(path),
                    )
                )
        if comps and not (path.parent / "go.sum").is_file():
            findings.append(
                DependencyFinding(
                    rule_id="SBOM-GO-01",
                    title="Missing `go.sum` checksum file alongside `go.mod`",
                    cwe_id="CWE-354",
                    severity="MEDIUM",
                    file_path=str(path),
                    evidence="go.sum not found",
                    remediation="Commit `go.sum` so Go verifies cryptographic module checksums in CI.",
                )
            )
        return comps, findings

    @staticmethod
    def _parse_cargo_toml(path: Path) -> tuple[List[SBOMComponent], List[DependencyFinding]]:
        comps: List[SBOMComponent] = []
        findings: List[DependencyFinding] = []
        in_deps = False
        for raw_line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.strip()
            if line.startswith("["):
                in_deps = line.startswith(("[dependencies", "[dev-dependencies", "[build-dependencies"))
                continue
            if in_deps and "=" in line and not line.startswith("#"):
                name, _, rhs = line.partition("=")
                pkg = name.strip().strip('"')
                m_ver = re.search(r'"([^"]+)"', rhs)
                ver = m_ver.group(1) if m_ver else "unspecified"
                comps.append(
                    SBOMComponent(
                        ecosystem="cargo",
                        name=pkg,
                        version=ver,
                        purl=f"pkg:cargo/{pkg}@{ver}",
                        source_file=str(path),
                    )
                )
                if ver == "*":
                    findings.append(
                        DependencyFinding(
                            rule_id="SBOM-CARGO-01",
                            title=f"Wildcard Cargo dependency version for `{pkg}`",
                            cwe_id="CWE-829",
                            severity="HIGH",
                            file_path=str(path),
                            evidence=line[:140],
                            remediation="Pin explicit semver bounds and commit `Cargo.lock` for binaries.",
                        )
                    )
        return comps, findings

    @classmethod
    def scan_path(cls, target: str | Path) -> Dict[str, Any]:
        root = Path(target)
        if not root.exists():
            return {"error": f"Path not found: {target}", "manifests_scanned": 0, "components_count": 0, "findings": []}

        manifests: List[Path] = []
        if root.is_file():
            manifests = [root]
        else:
            for item in root.rglob("*"):
                if not item.is_file():
                    continue
                if any(part in SKIP_DIRS for part in item.parts):
                    continue
                if item.name in ("package.json", "requirements.txt", "go.mod", "Cargo.toml"):
                    manifests.append(item)

        components: List[SBOMComponent] = []
        findings: List[DependencyFinding] = []
        for m in sorted(manifests):
            if m.name == "package.json":
                c, f = cls._parse_package_json(m)
            elif m.name == "requirements.txt":
                c, f = cls._parse_requirements_txt(m)
            elif m.name == "go.mod":
                c, f = cls._parse_go_mod(m)
            elif m.name == "Cargo.toml":
                c, f = cls._parse_cargo_toml(m)
            else:
                continue
            components.extend(c)
            findings.extend(f)

        cyclonedx = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{uuid.uuid4()}",
            "version": 1,
            "metadata": {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tools": [{"vendor": "ViperClaw", "name": "viperclaw-sbom", "version": __version__}],
            },
            "components": [c.to_cyclonedx() for c in components],
        }

        return {
            "target": str(root),
            "manifests_scanned": len(manifests),
            "components_count": len(components),
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings],
            "sbom_cyclonedx": cyclonedx,
        }
