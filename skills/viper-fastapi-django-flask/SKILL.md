---
name: viper-fastapi-django-flask
description: Python Web Framework Security Auditor (FastAPI, Django, Flask). Reviews FastAPI Depends() auth, Pydantic extra='forbid', Django RawSQL/@csrf_exempt, and Jinja2 autoescaping.
---

# ViperClaw Skill 38: FastAPI, Django & Flask Security Auditor (`viper-fastapi-django-flask`)

## 1. Standards & Open-Source Reference
- **Standards:** Bandit, Trail of Bits Python rules, Semgrep `p/fastapi`, `p/django`, `p/flask`, OWASP ASVS.
- **Focus:** Framework-specific authentication, ORM parameterization, serialization, and configuration auditing for Python web stacks.

## 2. Rapid Discovery Patterns
- **FastAPI:** `@app.post`, `@router.`, `Depends(`, `SQLAlchemy`, `text(`, `response_model=`.
- **Django:** `DEBUG =`, `ALLOWED_HOSTS`, `@csrf_exempt`, `.raw(`, `.extra(`, `RawSQL(`, `mark_safe`.
- **Flask:** `render_template_string`, `|safe`, `Markup(`, `session[`, `send_from_directory`.

## 3. Technical Audit Checklist
1. **FastAPI Dependency Auth & Output Filtering:** Verify all protected routers declare `dependencies=[Depends(get_current_user)]` at the `APIRouter` level and every endpoint defines a strict `response_model` (excluding `hashed_password` / internal fields) plus `model_config = ConfigDict(extra="forbid")` on input models.
2. **Django ORM Escape Hatch Audit:** Audit every use of `.raw()`, `.extra()`, and `RawSQL()` to ensure parameters are passed via the `params=[]` argument rather than Python f-strings.
3. **Django & Flask CSRF / Debug Hardening:** Confirm `DEBUG = False`, non-wildcard `ALLOWED_HOSTS`, high-entropy `SECRET_KEY` loaded from environment, and verify any `@csrf_exempt` view enforces HMAC or Bearer token authentication.
4. **Jinja2 / Django Template Injection & XSS:** Never pass user input into `Flask.render_template_string()` or `jinja2.Template()` (SSTI); avoid `mark_safe()`, `Markup()`, and `|safe` unless sanitized with `nh3` / `bleach`.
5. **Async SQLAlchemy Session Isolation:** In FastAPI async routes, ensure `AsyncSession` instances are scoped per-request via `Depends(get_db)` and never shared across concurrent coroutines.

## 4. Vulnerable vs. Hardened Pattern
```python
# ❌ VULNERABLE: FastAPI route returns full ORM model & uses f-string in SQLAlchemy text()
@router.get("/users/{username}")
async def get_user(username: str, db: AsyncSession = Depends(get_db)):
    res = await db.execute(text(f"SELECT * FROM users WHERE username = '{username}'"))
    return res.mappings().first()

# ✅ HARDENED: Requires auth dependency, binds SQL parameters & filters output via response_model
@router.get("/users/me", response_model=UserPublicDTO)
async def get_user(current_user: User = Depends(get_current_active_user), db: AsyncSession = Depends(get_db)):
    stmt = select(User).where(User.id == current_user.id)
    return (await db.execute(stmt)).scalar_one()
```
