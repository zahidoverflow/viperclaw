---
name: viper-php-laravel-wordpress
description: PHP, Laravel & WordPress Security Auditor. Reviews Laravel $fillable/$guarded mass assignment, Blade {!! !!}, DB::raw, WordPress nonces/$wpdb->prepare, and strict === comparison.
---

# ViperClaw Skill 43: PHP, Laravel & WordPress Security Auditor (`viper-php-laravel-wordpress`)

## 1. Standards & Open-Source Reference
- **Standards:** OWASP PHP Configuration Cheat Sheet, Enlightn (Laravel Security Analyzer), WordPress VIP Coding Standards.
- **Focus:** Auditing modern PHP 8+, Laravel, Symfony, and WordPress plugins/themes.

## 2. Rapid Discovery Patterns
- **Laravel:** `$guarded = []`, `Model::create($request->all())`, `DB::raw(`, `whereRaw(`, `{!! `, `unserialize(`.
- **WordPress:** `$_POST`, `$_GET`, `$wpdb->query(`, `wp_ajax_nopriv_`, `update_option(`.

## 3. Technical Audit Checklist
1. **Laravel Mass Assignment & FormRequest Validation:** Never pass `$request->all()` into `Model::create()` or `$model->update()` nor set `protected $guarded = []` on Eloquent models containing privilege/tenant columns; use `$request->validated()` with explicit `FormRequest` rules.
2. **Laravel Raw SQL & Query Builder Column Names:** Audit `DB::raw()`, `whereRaw()`, `orderByRaw()`, and note that column/sort names in `$query->orderBy($request->input('sort'))` must be validated against `in_array($sort, ['created_at', 'name'], true)`.
3. **Blade & Twig Output Escaping:** Replace unescaped `{!! $userContent !!}` with escaped `{{ $userContent }}` unless sanitized via `HTMLPurifier`.
4. **WordPress Capability + Nonce Dual Check:** Every `wp_ajax_*`, REST route, or admin action must check *both* `current_user_can('manage_options')` (authorization) *and* `check_ajax_referer()` / `wp_verify_nonce()` (CSRF), and parameterize SQL via `$wpdb->prepare()`.
5. **PHP Strict Comparison & File Inclusion:** Use strict equality `===` / `!==` and `in_array(..., true)` to prevent type-juggling bypasses, and disable `allow_url_include = Off` in `php.ini`.

## 4. Vulnerable vs. Hardened Pattern
```php
// ❌ VULNERABLE: Mass assignment of all request inputs & raw SQL interpolation
User::create($request->all());
$users = DB::select("SELECT * FROM users WHERE role = '" . $request->input('role') . "'");

// ✅ HARDENED: Validated DTO attributes & bound query parameters
User::create($request->safe()->only(['name', 'email']));
$users = DB::select("SELECT * FROM users WHERE role = ?", [$request->validated('role')]);
```
