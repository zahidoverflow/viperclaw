"""
Hardcoded Secrets & High-Entropy Credential Scanner (`viperclaw.analyzers.secrets_scanner`).

Zero-dependency static secret detector modeled on Gitleaks and TruffleHog patterns:
- Scans source files, `.env` configs, CI YAML, Dockerfiles, and JSON/TOML manifests.
- Combines vendor-specific credential regex rules with Shannon entropy scoring.
- Automatically masks matched values in output so raw credentials are never echoed verbatim.
"""

from __future__ import annotations

import math
import re
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List


SKIP_DIRS = {
    ".git",
    "node_modules",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    "dist",
    "build",
    ".next",
    ".viperclaw",
}

SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".php", ".rb", ".java", ".rs",
    ".json", ".yml", ".yaml", ".toml", ".ini", ".cfg", ".conf", ".env",
    ".sh", ".bash", ".tf", ".tfvars", ".xml", ".properties", ".txt", ".md",
}

SECRET_RULES: List[Dict[str, Any]] = [
    {
        "rule_id": "SEC-AWS-KEY",
        "title": "AWS Access Key ID",
        "cwe_id": "CWE-798",
        "severity": "HIGH",
        "pattern": re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    },
    {
        "rule_id": "SEC-GH-TOKEN",
        "title": "GitHub Personal Access Token",
        "cwe_id": "CWE-798",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\b(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{30,}|gho_[A-Za-z0-9]{36})\b"),
    },
    {
        "rule_id": "SEC-GOOGLE-API",
        "title": "Google Cloud / Firebase API Key",
        "cwe_id": "CWE-798",
        "severity": "HIGH",
        "pattern": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    },
    {
        "rule_id": "SEC-STRIPE-LIVE",
        "title": "Stripe Live Secret Key",
        "cwe_id": "CWE-798",
        "severity": "CRITICAL",
        "pattern": re.compile(r"\bsk_live_[0-9A-Za-z]{20,}\b"),
    },
    {
        "rule_id": "SEC-SLACK-TOKEN",
        "title": "Slack API / Bot Token",
        "cwe_id": "CWE-798",
        "severity": "HIGH",
        "pattern": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,48}\b"),
    },
    {
        "rule_id": "SEC-OPENAI-KEY",
        "title": "OpenAI / Anthropic API Key",
        "cwe_id": "CWE-798",
        "severity": "HIGH",
        "pattern": re.compile(r"\b(?:sk-proj-[A-Za-z0-9_\-]{20,}|sk-ant-[A-Za-z0-9_\-]{20,})\b"),
    },
    {
        "rule_id": "SEC-PRIVATE-KEY",
        "title": "PEM Private Key Material",
        "cwe_id": "CWE-321",
        "severity": "CRITICAL",
        "pattern": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    },
    {
        "rule_id": "SEC-DB-URI",
        "title": "Database Connection URI with Embedded Credentials",
        "cwe_id": "CWE-798",
        "severity": "HIGH",
        "pattern": re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp)://[^/\s:@]+:[^/\s@]{6,}@[^\s\"']+"),
    },
]

GENERIC_ASSIGN_RE = re.compile(
    r"""(?i)\b([a-z0-9_]*(?:secret|api[_-]?key|access[_-]?token|auth[_-]?token|private[_-]?key|client[_-]?secret|passwd|password)[a-z0-9_]*)\s*[:=]\s*["']([A-Za-z0-9+/=_\-.]{16,128})["']"""
)

PLACEHOLDER_HINTS = (
    "example",
    "placeholder",
    "changeme",
    "your_",
    "your-",
    "dummy",
    "sample",
    "fake",
    "test_",
    "xxxx",
    "redacted",
    "<your",
    "${",
)


@dataclass
class SecretFinding:
    rule_id: str
    title: str
    cwe_id: str
    severity: str
    file_path: str
    line_number: int
    masked_match: str
    entropy: float

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SecretsScanner:
    """Zero-dependency regex + Shannon-entropy secret scanner."""

    @staticmethod
    def shannon_entropy(value: str) -> float:
        if not value:
            return 0.0
        counts: Dict[str, int] = {}
        for ch in value:
            counts[ch] = counts.get(ch, 0) + 1
        length = len(value)
        return round(-sum((c / length) * math.log2(c / length) for c in counts.values()), 3)

    @staticmethod
    def mask_value(value: str) -> str:
        clean = value.strip()
        if len(clean) <= 10:
            return clean[:2] + "***"
        return f"{clean[:4]}...{clean[-4:]}"

    @staticmethod
    def _is_placeholder(val: str) -> bool:
        low = val.lower()
        return any(h in low for h in PLACEHOLDER_HINTS)

    @classmethod
    def scan_file(cls, file_path: Path) -> List[SecretFinding]:
        findings: List[SecretFinding] = []
        try:
            text = file_path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return findings

        seen: set[tuple[str, int, str]] = set()
        for line_no, line in enumerate(text.splitlines(), 1):
            if len(line) > 4096:
                continue
            for rule in SECRET_RULES:
                for m in rule["pattern"].finditer(line):
                    raw = m.group(0)
                    if cls._is_placeholder(raw):
                        continue
                    masked = cls.mask_value(raw)
                    key = (rule["rule_id"], line_no, masked)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        SecretFinding(
                            rule_id=rule["rule_id"],
                            title=rule["title"],
                            cwe_id=rule["cwe_id"],
                            severity=rule["severity"],
                            file_path=str(file_path),
                            line_number=line_no,
                            masked_match=masked,
                            entropy=cls.shannon_entropy(raw),
                        )
                    )

            for gm in GENERIC_ASSIGN_RE.finditer(line):
                var_name, val = gm.group(1), gm.group(2)
                if cls._is_placeholder(val):
                    continue
                ent = cls.shannon_entropy(val)
                if ent >= 3.8:
                    masked = f"{var_name}={cls.mask_value(val)}"
                    key = ("SEC-HIGH-ENTROPY", line_no, masked)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append(
                        SecretFinding(
                            rule_id="SEC-HIGH-ENTROPY",
                            title="High-Entropy Hardcoded Credential Assignment",
                            cwe_id="CWE-798",
                            severity="MEDIUM",
                            file_path=str(file_path),
                            line_number=line_no,
                            masked_match=masked,
                            entropy=ent,
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
                if item.suffix.lower() in SCAN_EXTENSIONS or item.name.startswith(".env") or item.name.startswith("Dockerfile"):
                    if item.stat().st_size <= 2_000_000:
                        files.append(item)

        all_findings: List[SecretFinding] = []
        for f in sorted(files):
            all_findings.extend(cls.scan_file(f))

        return {
            "target": str(root),
            "files_scanned": len(files),
            "total_findings": len(all_findings),
            "findings": [f.to_dict() for f in all_findings],
        }
