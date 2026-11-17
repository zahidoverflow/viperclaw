---
name: viper-crypto-tls-audit
description: Cryptography, Key Management & Password Hashing Auditor (modeled on Trail of Bits & OWASP Cryptographic Storage). Reviews algorithms, IV/nonce handling, CSPRNG usage, and Argon2/bcrypt.
---

# ViperClaw Skill 21: Cryptography, Key Management & Hashing Auditor (`viper-crypto-tls-audit`)

## Overview
Audits cryptographic code, key derivation, random token generation, and TLS settings for weak primitives (CWE-327, CWE-338, CWE-916).

## Audit Checklist
1. **Password & Secret Hashing:** Ensure passwords use memory-hard `Argon2id`, `bcrypt`, or `scrypt` with appropriate work factors—never fast hashes (`MD5`, `SHA-1`, `SHA-256` without KDF).
2. **Authenticated Encryption & Nonce Safety:** Prefer AEAD modes (`AES-GCM`, `ChaCha20-Poly1305`) over unauthenticated `AES-CBC`/`AES-ECB`, and never reuse nonces/IVs.
3. **CSPRNG Enforcement:** Use cryptographically secure random generators (`secrets` in Python, `crypto.randomBytes`/`crypto.randomUUID` in Node, `crypto/rand` in Go) for tokens, salts, and session IDs.
