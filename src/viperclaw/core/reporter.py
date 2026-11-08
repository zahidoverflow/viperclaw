"""
Multi-Format Report & SARIF 2.1.0 Generator (`viperclaw.core.reporter`).

Exports verified findings into:
1. Impact-First Bug Bounty Markdown Reports (HackerOne / Bugcrowd / Intigriti ready).
2. SARIF 2.1.0 JSON for GitHub Code Scanning & CI/CD pull-request gates.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List


@dataclass
class VerifiedFinding:
    finding_id: str
    title: str
    vuln_class: str
    asset: str
    cvss_score: float
    cvss_severity: str
    cvss_vector: str
    cwe_id: str = "CWE-284"
    summary: str = ""
    steps_to_reproduce: List[str] = field(default_factory=list)
    request_receipt: str = ""
    response_receipt: str = ""
    impact: str = ""
    remediation: str = ""
    file_path: str = ""
    line_number: int = 1

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ReportGenerator:
    """Generates submission-ready Markdown reports and SARIF 2.1.0 artifacts."""

    @staticmethod
    def to_bounty_markdown(finding: VerifiedFinding) -> str:
        steps = "\n".join(f"{idx}. {step}" for idx, step in enumerate(finding.steps_to_reproduce, 1))
        if not steps:
            steps = "1. Replay the attached HTTP request receipt against the target endpoint.\n2. Observe the unauthorized data/state change in the response receipt."

        return f"""# [{finding.cvss_severity}] {finding.title}

| Metric | Value |
| :--- | :--- |
| **Target Asset** | `{finding.asset}` |
| **Vulnerability Class** | {finding.vuln_class} (`{finding.cwe_id}`) |
| **Severity / CVSS 3.1** | **{finding.cvss_severity} ({finding.cvss_score})** — `{finding.cvss_vector}` |
| **Verification Status** | `VERIFIED_BY_VIPERCLAW_ORACLE` |

---

## Executive Summary
{finding.summary or f"An attacker can exploit a {finding.vuln_class} vulnerability on `{finding.asset}` to cross trust boundaries and impact confidentiality/integrity."}

## Impact
{finding.impact or "Direct unauthorized access to protected resources or execution of privileged actions across tenant boundaries."}

## Steps to Reproduce
{steps}

## Proof-of-Concept Receipts

### Request / Command Receipt
```http
{finding.request_receipt.strip()}
```

### Verified Response Receipt
```http
{finding.response_receipt.strip()}
```

## Recommended Remediation
{finding.remediation or "Enforce strict server-side authorization and input validation at the controller/resolver layer prior to executing state or data operations."}
"""

    @staticmethod
    def to_sarif(findings: List[VerifiedFinding], tool_version: str = "1.0.0") -> Dict[str, Any]:
        rules = []
        results = []
        seen_rules = set()

        for f in findings:
            rule_id = f"{f.cwe_id}:{f.vuln_class.lower().replace(' ', '_')}"
            if rule_id not in seen_rules:
                seen_rules.add(rule_id)
                rules.append(
                    {
                        "id": rule_id,
                        "name": f.vuln_class,
                        "shortDescription": {"text": f.title},
                        "helpUri": "https://github.com/zahidoverflow/viperclaw",
                        "properties": {
                            "security-severity": str(f.cvss_score),
                            "tags": ["security", "viperclaw", f.cwe_id.lower()],
                        },
                    }
                )

            level = "error" if f.cvss_score >= 7.0 else ("warning" if f.cvss_score >= 4.0 else "note")
            results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "message": {"text": f"{f.title} — {f.summary} ({f.cvss_vector})"},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.file_path or f.asset},
                                "region": {"startLine": max(1, f.line_number)},
                            }
                        }
                    ],
                }
            )

        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Sarif-2.1.0/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "ViperClaw",
                            "version": tool_version,
                            "informationUri": "https://github.com/zahidoverflow/viperclaw",
                            "rules": rules,
                        }
                    },
                    "results": results,
                }
            ],
        }

    @classmethod
    def to_sarif_json(cls, findings: List[VerifiedFinding], indent: int = 2) -> str:
        return json.dumps(cls.to_sarif(findings), indent=indent)
