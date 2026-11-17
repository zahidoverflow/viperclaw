---
name: viper-deserialization-parser
description: Safe Deserialization & XML/YAML/JSON Parser Auditor (OWASP Deserialization Cheat Sheet). Reviews pickle/yaml/marshal/unserialize usage and XXE entity resolution.
---

# ViperClaw Skill 25: Safe Deserialization & Parser Security Auditor (`viper-deserialization-parser`)

## Overview
Audits data parsing and object deserialization code across Python, Java, PHP, Ruby, and Node.js to eliminate insecure deserialization (CWE-502) and XML External Entity (XXE, CWE-611) risks.

## Audit Checklist
1. **Eliminate Native Object Deserialization on Untrusted Data:** Replace `pickle.loads`, `yaml.load` (without `SafeLoader`), PHP `unserialize()`, Java `ObjectInputStream`, and Ruby `Marshal.load` with safe data formats (`json.loads`, `yaml.safe_load`, Protobuf).
2. **XML Parser Hardening (XXE Prevention):** Disable DTDs (`disallow-doctype-decl`) and external general/parameter entities in XML parsers (or use `defusedxml` in Python).
3. **Prototype Pollution Prevention (JS/TS):** Avoid recursive deep-merge on untrusted JSON objects without filtering `__proto__`, `constructor`, and `prototype` keys.
