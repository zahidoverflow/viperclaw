---
name: viper-injection-oracle
description: Input Validation & Query Parameterization Auditor. Reviews SQL, NoSQL, template rendering, and OS command execution paths to ensure strict parameterization and type safety.
---

# ViperClaw Skill 05: Input Validation & Parameterization Auditor (`viper-injection-oracle`)

## Overview
Audits data-access layers, template engines, and subprocess calls to eliminate injection weaknesses (CWE-89, CWE-78, CWE-943, CWE-1336) through code review and non-destructive diagnostics.

## Audit Checklist
1. **Database Query Parameterization:** Ensure all SQL queries use prepared statements / bound parameters (`PDO::prepare`, `cursor.execute(sql, params)`) and dynamic `ORDER BY` clauses use strict allowlists.
2. **NoSQL Type Enforcement:** Confirm request parameters passed to document queries are cast to scalar strings/integers rather than raw nested objects/operators.
3. **Subprocess & Template Safety:** Replace shell command strings (`shell=True`, `os.system`) with argument arrays (`subprocess.run([...], shell=False)`) and auto-escaped templates.
