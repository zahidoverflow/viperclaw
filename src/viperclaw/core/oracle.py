"""
Wire-Check Proof Oracle & 7-Gate Triage Validator (`viperclaw.core.oracle`).

Enforces ViperClaw's core axiom: "No Receipt, No Report."
- Detects WAF soft-blocks ("200 OK" pages that are actually Cloudflare/Akamai/Imperva blocks).
- Computes deterministic HTTP response differentials (status, structural JSON keys, body similarity,
  timing deltas, reflection context) for BOLA/IDOR and injection validation.
- Evaluates the 7-Question Pre-Submission Gate and calculates exact CVSS 3.1 base scores.
"""

from __future__ import annotations

import difflib
import json
import math
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional


WAF_SOFT_BLOCK_PATTERNS = [
    (r"(?i)attention required!?\s*\|\s*cloudflare", "Cloudflare Challenge"),
    (r"(?i)just a moment\.{0,3}</title>", "Cloudflare Turnstile / JS Challenge"),
    (r"(?i)access denied.*reference\s*#[0-9a-f\.]+", "Akamai Ghost Block"),
    (r"(?i)incapsula incident id", "Imperva / Incapsula WAF"),
    (r"(?i)request blocked by.*cloudfront", "AWS CloudFront WAF"),
    (r"(?i)automated access to this page has been denied", "PerimeterX / HUMAN Bot Defender"),
    (r"(?i)datadome.*captcha", "DataDome Anti-Bot"),
]

ALWAYS_REJECTED_PATTERNS = [
    r"(?i)\bmissing\s+(x-frame-options|content-security-policy|strict-transport-security|hsts|x-content-type-options)\b",
    r"(?i)\b(spf|dmarc|dkim)\s+record\s+(missing|softfail|none)\b",
    r"(?i)\bserver\s+version\s+disclosure\b",
    r"(?i)\bself[- ]xss\b",
    r"(?i)\bclickjacking\s+on\s+non[- ]sensitive\b",
    r"(?i)\bcors\s+wildcard\s+without\s+credentials\b",
    r"(?i)\boptions\s+method\s+enabled\b",
]


@dataclass
class HttpSample:
    status_code: int
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    elapsed_ms: float = 0.0


@dataclass
class DifferentialVerdict:
    is_waf_soft_block: bool
    waf_vendor: Optional[str]
    status_changed: bool
    similarity_ratio: float
    length_delta: int
    json_keys_added: List[str]
    json_keys_removed: List[str]
    timing_anomaly: bool
    bola_CONFIRMED_hint: bool
    notes: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class TriageVerdict:
    passed: bool
    verdict: str  # "VERIFIED_SUBMITTABLE", "NEEDS_CHAIN", "REJECTED_NOISE"
    cvss_score: float
    cvss_severity: str
    cvss_vector: str
    gates_passed: Dict[str, bool]
    rejection_reasons: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ProofOracle:
    """Deterministic HTTP Differential & 7-Gate Triage Oracle."""

    @staticmethod
    def detect_waf_soft_block(sample: HttpSample) -> Optional[str]:
        combined = f"{json.dumps(sample.headers)}\n{sample.body[:4096]}"
        for pattern, vendor in WAF_SOFT_BLOCK_PATTERNS:
            if re.search(pattern, combined):
                return vendor
        if sample.status_code == 200 and len(sample.body.strip()) < 45 and "denied" in sample.body.lower():
            return "Generic Soft-200 Access Denied"
        return None

    @staticmethod
    def _extract_json_keys(body: str) -> List[str]:
        try:
            parsed = json.loads(body)
        except Exception:
            return []

        keys: List[str] = []

        def _walk(obj: Any, prefix: str = "") -> None:
            if isinstance(obj, dict):
                for k, v in obj.items():
                    path = f"{prefix}.{k}" if prefix else k
                    keys.append(path)
                    _walk(v, path)
            elif isinstance(obj, list) and obj:
                _walk(obj[0], f"{prefix}[]")

        _walk(parsed)
        return sorted(set(keys))

    @classmethod
    def compare_samples(
        cls,
        baseline: HttpSample,
        probe: HttpSample,
        unauth_or_other_tenant: Optional[HttpSample] = None,
    ) -> DifferentialVerdict:
        """
        Compare a baseline HTTP response against a mutated/cross-tenant probe response.
        Optionally compares against an unauthenticated baseline to confirm BOLA/IDOR.
        """
        waf = cls.detect_waf_soft_block(probe)
        status_changed = baseline.status_code != probe.status_code
        sim = round(
            difflib.SequenceMatcher(None, baseline.body[:10000], probe.body[:10000]).ratio(),
            4,
        )
        length_delta = len(probe.body) - len(baseline.body)

        base_keys = set(cls._extract_json_keys(baseline.body))
        probe_keys = set(cls._extract_json_keys(probe.body))
        added_keys = sorted(probe_keys - base_keys)
        removed_keys = sorted(base_keys - probe_keys)

        timing_anomaly = (probe.elapsed_ms - baseline.elapsed_ms) >= 3500.0
        notes: List[str] = []

        if waf:
            notes.append(f"Probe triggered WAF/Anti-Bot block: {waf}")

        bola_hint = False
        if (
            not waf
            and probe.status_code == 200
            and baseline.status_code == 200
            and sim >= 0.75
            and len(probe.body) > 30
        ):
            if unauth_or_other_tenant is None or unauth_or_other_tenant.status_code in (401, 403, 404):
                bola_hint = True
                notes.append(
                    "Cross-tenant probe returned 200 OK matching authorized schema while unauth is blocked (High BOLA/IDOR signal)."
                )

        if timing_anomaly:
            notes.append(
                f"Timing delta of +{probe.elapsed_ms - baseline.elapsed_ms:.0f}ms detected (Time-based oracle candidate)."
            )

        return DifferentialVerdict(
            is_waf_soft_block=waf is not None,
            waf_vendor=waf,
            status_changed=status_changed,
            similarity_ratio=sim,
            length_delta=length_delta,
            json_keys_added=added_keys,
            json_keys_removed=removed_keys,
            timing_anomaly=timing_anomaly,
            bola_CONFIRMED_hint=bola_hint,
            notes=notes,
        )

    @staticmethod
    def calculate_cvss31(
        av: str = "N",
        ac: str = "L",
        pr: str = "N",
        ui: str = "N",
        scope: str = "U",
        c: str = "H",
        i: str = "H",
        a: str = "N",
    ) -> tuple[float, str, str]:
        """Calculate exact CVSS v3.1 Base Score, Severity, and Vector String."""
        av_map = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
        ac_map = {"L": 0.77, "H": 0.44}
        ui_map = {"N": 0.85, "R": 0.62}
        cia_map = {"N": 0.0, "L": 0.22, "H": 0.56}
        pr_map_u = {"N": 0.85, "L": 0.62, "H": 0.27}
        pr_map_c = {"N": 0.85, "L": 0.68, "H": 0.50}

        pr_val = pr_map_c[pr] if scope == "C" else pr_map_u[pr]
        iss = 1.0 - ((1.0 - cia_map[c]) * (1.0 - cia_map[i]) * (1.0 - cia_map[a]))

        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)

        exploitability = 8.22 * av_map[av] * ac_map[ac] * pr_val * ui_map[ui]

        if impact <= 0:
            score = 0.0
        elif scope == "U":
            score = math.ceil(min(impact + exploitability, 10.0) * 10.0) / 10.0
        else:
            score = math.ceil(min(1.08 * (impact + exploitability), 10.0) * 10.0) / 10.0

        if score == 0.0:
            severity = "NONE"
        elif score <= 3.9:
            severity = "LOW"
        elif score <= 6.9:
            severity = "MEDIUM"
        elif score <= 8.9:
            severity = "HIGH"
        else:
            severity = "CRITICAL"

        vector = f"CVSS:3.1/AV:{av}/AC:{ac}/PR:{pr}/UI:{ui}/S:{scope}/C:{c}/I:{i}/A:{a}"
        return score, severity, vector

    @classmethod
    def evaluate_7_gates(
        cls,
        title: str,
        evidence_request: str,
        evidence_response: str,
        in_scope: bool = True,
        cross_boundary_proven: bool = True,
        cvss_params: Optional[Dict[str, str]] = None,
    ) -> TriageVerdict:
        """
        Evaluate a candidate finding against the 7-Question Pre-Submission Gate:
        1. Not on the Always-Rejected scanner noise list
        2. Asset is confirmed in scope
        3. Concrete raw HTTP request/command receipt attached
        4. Concrete raw response/output receipt attached (and not a WAF soft-block)
        5. Exploitable across a real trust/auth boundary (not self-only)
        6. Demonstrates measurable CIA impact (not theoretical 'could potentially')
        7. CVSS 3.1 base score >= 4.0 (or chained to reach Medium/High/Critical)
        """
        reasons: List[str] = []

        not_noise = True
        for pat in ALWAYS_REJECTED_PATTERNS:
            if re.search(pat, title):
                not_noise = False
                reasons.append(f"Title matches always-rejected scanner pattern: '{title}'")
                break

        has_req = len(evidence_request.strip()) >= 12
        if not has_req:
            reasons.append("Missing concrete reproducible request/command receipt.")

        waf_check = cls.detect_waf_soft_block(HttpSample(status_code=200, body=evidence_response))
        has_resp = len(evidence_response.strip()) >= 12 and waf_check is None
        if waf_check:
            reasons.append(f"Response receipt is a WAF soft-block ({waf_check}), not a valid exploit.")
        elif not has_resp:
            reasons.append("Missing concrete response/output receipt.")

        non_theoretical = not bool(
            re.search(r"(?i)\b(could potentially|might allow|theoretical|unverified)\b", title)
        )
        if not non_theoretical:
            reasons.append("Finding relies on speculative/theoretical phrasing instead of proven impact.")

        if not in_scope:
            reasons.append("Target asset is not confirmed in scope.")

        if not cross_boundary_proven:
            reasons.append("Cross-user or trust-boundary impact is not proven (self-only or unverified).")

        params = cvss_params or {}
        score, severity, vector = cls.calculate_cvss31(**params)
        impact_gate = score >= 4.0
        if not impact_gate:
            reasons.append(f"CVSS score ({score} {severity}) is below 4.0; requires chaining before submission.")

        gates = {
            "1_not_scanner_noise": not_noise,
            "2_in_scope": in_scope,
            "3_has_request_receipt": has_req,
            "4_has_valid_response_receipt": has_resp,
            "5_cross_trust_boundary": cross_boundary_proven,
            "6_non_theoretical_impact": non_theoretical,
            "7_cvss_threshold_met": impact_gate,
        }

        passed = all(gates.values())
        if passed:
            verdict = "VERIFIED_SUBMITTABLE"
        elif not_noise and has_req and has_resp and not impact_gate:
            verdict = "NEEDS_CHAIN"
        else:
            verdict = "REJECTED_NOISE"

        return TriageVerdict(
            passed=passed,
            verdict=verdict,
            cvss_score=score,
            cvss_severity=severity,
            cvss_vector=vector,
            gates_passed=gates,
            rejection_reasons=reasons,
        )
