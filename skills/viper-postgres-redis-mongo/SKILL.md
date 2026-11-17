---
name: viper-postgres-redis-mongo
description: Database & Cache Security Auditor (PostgreSQL, Redis, MongoDB). Reviews PostgreSQL SECURITY DEFINER search_path & RLS, Redis ACLs, and MongoDB operator sanitization.
---

# ViperClaw Skill 52: PostgreSQL, Redis & MongoDB Security Auditor (`viper-postgres-redis-mongo`)

## 1. Standards & Open-Source Reference
- **Standards:** CIS PostgreSQL / MongoDB / Redis Benchmarks, OWASP Database Security Cheat Sheet.
- **Focus:** Auditing SQL migrations, stored procedures, PostgreSQL RLS policies, Redis configurations, and MongoDB queries.

## 2. Rapid Discovery Patterns
- **PostgreSQL:** `SECURITY DEFINER`, `ENABLE ROW LEVEL SECURITY`, `EXECUTE format(`, `GRANT ALL`.
- **Redis:** `bind 0.0.0.0`, `protected-mode no`, `KEYS *`, `EVAL `.
- **MongoDB:** `$where`, `$regex`, `express-mongo-sanitize`.

## 3. Technical Audit Checklist
1. **PostgreSQL `SECURITY DEFINER` `search_path` Hardening:** Every `SECURITY DEFINER` function in PostgreSQL must explicitly set `SET search_path = pg_catalog, public` in its definition to prevent schema-shadowing privilege escalation (CWE-426).
2. **PostgreSQL Dynamic SQL (`EXECUTE`) & RLS Completeness:** Inside PL/pgSQL functions, use `EXECUTE format('SELECT ... FROM %I WHERE id = $1', tbl) USING val` (`%I` for identifiers, `$1` for values, never `%s` for values); verify tables with `ENABLE ROW LEVEL SECURITY` also define policies for `INSERT`/`UPDATE`/`DELETE` (`WITH CHECK`).
3. **Redis Authentication, ACLs & Dangerous Commands:** Ensure Redis binds only to private interfaces (`bind 127.0.0.1`), enforces TLS + `requirepass` / Redis 6+ ACL users, and disables/renames `FLUSHALL`, `FLUSHDB`, `CONFIG`, `MODULE`, and `EVAL` for standard application roles.
4. **MongoDB Operator & `$where` Sanitization:** Disable server-side JavaScript execution (`--noscripting`), forbid `$where` and `mapReduce`, and strip keys starting with `$` or containing `.` from user inputs (`mongo-sanitize`) before passing to `.find()` / `.updateOne()`.
5. **Least-Privilege Application DB Roles:** The runtime web application should connect using a role that has `SELECT, INSERT, UPDATE, DELETE` on application tables only—never `SUPERUSER`, `rds_superuser`, or DDL (`DROP`/`ALTER`) privileges.

## 4. Vulnerable vs. Hardened Pattern
```sql
-- ❌ VULNERABLE: SECURITY DEFINER without search_path & unsafe %s value interpolation
CREATE FUNCTION get_user_email(uid int) RETURNS text AS $$
DECLARE res text;
BEGIN
  EXECUTE format('SELECT email FROM users WHERE id = %s', uid) INTO res;
  RETURN res;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

-- ✅ HARDENED: Pinned search_path & parameterized USING clause
CREATE FUNCTION get_user_email(uid int) RETURNS text AS $$
DECLARE res text;
BEGIN
  EXECUTE 'SELECT email FROM public.users WHERE id = $1' INTO res USING uid;
  RETURN res;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public;
```
