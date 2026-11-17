---
name: viper-file-upload-storage
description: File Upload, Path Traversal & Object Storage Security Auditor (OWASP File Upload Cheat Sheet). Reviews filename sanitization, MIME/magic-byte validation, and isolated storage.
---

# ViperClaw Skill 24: File Upload, Path Traversal & Storage Auditor (`viper-file-upload-storage`)

## Overview
Audits file upload handlers, archive extractors (`zip`/`tar`), and static file servers for unrestricted file upload (CWE-434), Zip Slip, and path traversal (CWE-22).

## Audit Checklist
1. **Random Server-Generated Filenames:** Never use raw client-supplied filenames (`Content-Disposition`) to construct filesystem paths; generate a random UUID filename and validate against a strict extension allowlist.
2. **Content & Archive Inspection:** Validate file magic bytes/image dimensions rather than trusting client `Content-Type`, and check every archive entry (`zipfile`/`tarfile`) to block `..` path traversal and symlinks.
3. **Isolated Non-Executable Storage:** Store user uploads outside the web root (or on a separate S3/CDN domain) and serve with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`.
