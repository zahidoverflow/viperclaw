"""
MCP Server & AI Agent Skill Supply-Chain Security Auditor (`viperclaw.analyzers.mcp_auditor`).

Zero-dependency static auditor modeled on OWASP MCP Top 10 and NVIDIA SkillSpector:
- Audits MCP JSON configs (`mcp_config.json`, `.mcp.json`, `opencode.json`, `claude_desktop_config.json`)
  for unpinned dynamic package runners (`npx -y`, `uvx`, `pipx`), hardcoded credentials in `env` /
  `environment` blocks, and unsafe shell invocations.
- Audits AI coding agent `SKILL.md` directories for hidden instruction-override phrases,
  invisible Unicode tag characters (`U+E0000`–`U+E007F`), and unverified pipe-to-shell commands.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List


SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", ".pytest_cache", ".viperclaw"}
MCP_CONFIG_NAMES = {"mcp_config.json", ".mcp.json", "opencode.json", "mcp.json", "claude_desktop_config.json"}
SENSITIVE_ENV_RE = re.compile(r"(?i)(token|secret|key|password|passwd|auth|credential)")


@dataclass
class MCPAuditFinding:
    rule_id: str
    target_type: str
    title: str
    cwe_id: str
    severity: str
    file_path: str
    evidence: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MCPAuditor:
    """Zero-dependency security auditor for MCP server configs and AI agent SKILL.md bundles."""

    @classmethod
    def _audit_mcp_config(cls, path: Path) -> List[MCPAuditFinding]:
        findings: List[MCPAuditFinding] = []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception:
            return findings
        if not isinstance(data, dict):
            return findings

        servers: Dict[str, Any] = {}
        if isinstance(data.get("mcpServers"), dict):
            servers.update(data["mcpServers"])
        if isinstance(data.get("mcp"), dict):
            servers.update(data["mcp"])

        for sname, cfg in servers.items():
            if not isinstance(cfg, dict):
                continue
            raw_cmd = cfg.get("command")
            raw_args = cfg.get("args") if isinstance(cfg.get("args"), list) else []
            if isinstance(raw_cmd, list):
                cmd_parts = [str(x) for x in raw_cmd]
            elif isinstance(raw_cmd, str):
                cmd_parts = [raw_cmd] + [str(x) for x in raw_args]
            else:
                cmd_parts = []
            cmd_joined = " ".join(cmd_parts)

            if cmd_parts and Path(cmd_parts[0]).name in ("npx", "uvx", "pipx"):
                has_pinned = any(re.search(r"@\d+\.\d+", part) or "==" in part for part in cmd_parts[1:])
                if not has_pinned:
                    findings.append(
                        MCPAuditFinding(
                            rule_id="MCP-CFG-01",
                            target_type="mcp_config",
                            title=f"MCP server `{sname}` uses unpinned dynamic runner (`{Path(cmd_parts[0]).name}`)",
                            cwe_id="CWE-829",
                            severity="HIGH",
                            file_path=str(path),
                            evidence=cmd_joined[:160],
                            remediation="Pin an exact package version or install a verified local binary instead of unpinned npx/uvx.",
                        )
                    )

            if cmd_parts and Path(cmd_parts[0]).name in ("sh", "bash", "zsh", "cmd", "powershell"):
                findings.append(
                    MCPAuditFinding(
                        rule_id="MCP-CFG-02",
                        target_type="mcp_config",
                        title=f"MCP server `{sname}` launches via an interactive shell wrapper",
                        cwe_id="CWE-78",
                        severity="MEDIUM",
                        file_path=str(path),
                        evidence=cmd_joined[:160],
                        remediation="Invoke the MCP binary directly with an explicit argument array instead of `sh -c`.",
                    )
                )

            env_map = cfg.get("env") or cfg.get("environment")
            if isinstance(env_map, dict):
                for ek, ev in env_map.items():
                    ev_str = str(ev).strip()
                    if SENSITIVE_ENV_RE.search(str(ek)) and len(ev_str) >= 12 and not ev_str.startswith(("$", "{")):
                        findings.append(
                            MCPAuditFinding(
                                rule_id="MCP-CFG-03",
                                target_type="mcp_config",
                                title=f"Plaintext credential in MCP server `{sname}` env var `{ek}`",
                                cwe_id="CWE-798",
                                severity="HIGH",
                                file_path=str(path),
                                evidence=f"{ek}={ev_str[:4]}...{ev_str[-3:]}",
                                remediation="Inject secrets from an OS keychain or environment reference instead of hardcoding in JSON.",
                            )
                        )
        return findings

    @classmethod
    def _audit_skill_md(cls, path: Path) -> List[MCPAuditFinding]:
        findings: List[MCPAuditFinding] = []
        try:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return findings

        if any(0xE0000 <= ord(ch) <= 0xE007F for ch in text):
            findings.append(
                MCPAuditFinding(
                    rule_id="MCP-SKILL-01",
                    target_type="skill_md",
                    title="Invisible Unicode tag characters detected inside SKILL.md",
                    cwe_id="CWE-116",
                    severity="CRITICAL",
                    file_path=str(path),
                    evidence="Contains Unicode Tag block characters (U+E0000-U+E007F)",
                    remediation="Strip all hidden Unicode tag characters and audit the skill source.",
                )
            )

        if re.search(r"curl\s+[^|\n]+\|\s*(?:ba)?sh|wget\s+[^|\n]+\|\s*(?:ba)?sh", text, re.I):
            findings.append(
                MCPAuditFinding(
                    rule_id="MCP-SKILL-02",
                    target_type="skill_md",
                    title="Skill instructions contain unverified remote pipe-to-shell command",
                    cwe_id="CWE-494",
                    severity="HIGH",
                    file_path=str(path),
                    evidence="Matched `curl/wget ... | sh/bash` pattern in SKILL.md",
                    remediation="Replace pipe-to-shell instructions with pinned package installs and checksum verification.",
                )
            )

        if re.search(r"(?i)ignore\s+(?:all\s+)?previous\s+instructions|disregard\s+system\s+prompt", text):
            findings.append(
                MCPAuditFinding(
                    rule_id="MCP-SKILL-03",
                    target_type="skill_md",
                    title="Skill contains prompt-boundary override directive",
                    cwe_id="CWE-74",
                    severity="HIGH",
                    file_path=str(path),
                    evidence="Matched prompt override phrasing in SKILL.md",
                    remediation="Remove instruction-override directives and verify skill provenance.",
                )
            )
        return findings

    @classmethod
    def scan_path(cls, target: str | Path) -> Dict[str, Any]:
        root = Path(target)
        if not root.exists():
            return {"error": f"Path not found: {target}", "files_scanned": 0, "total_findings": 0, "findings": []}

        findings: List[MCPAuditFinding] = []
        scanned = 0
        if root.is_file():
            if root.name == "SKILL.md":
                scanned = 1
                findings.extend(cls._audit_skill_md(root))
            elif root.suffix.lower() == ".json":
                scanned = 1
                findings.extend(cls._audit_mcp_config(root))
        else:
            for item in sorted(root.rglob("*")):
                if not item.is_file():
                    continue
                if any(part in SKIP_DIRS for part in item.parts):
                    continue
                if item.name == "SKILL.md":
                    scanned += 1
                    findings.extend(cls._audit_skill_md(item))
                elif item.name in MCP_CONFIG_NAMES:
                    scanned += 1
                    findings.extend(cls._audit_mcp_config(item))

        return {
            "target": str(root),
            "files_scanned": scanned,
            "total_findings": len(findings),
            "findings": [f.to_dict() for f in findings],
        }
