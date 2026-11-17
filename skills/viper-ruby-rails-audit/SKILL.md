---
name: viper-ruby-rails-audit
description: Ruby on Rails & Rack Security Auditor (modeled on Brakeman). Reviews Strong Parameters, dynamic send/constantize, render inline, Marshal cookies, and ActiveRecord SQL.
---

# ViperClaw Skill 44: Ruby on Rails & Rack Security Auditor (`viper-ruby-rails-audit`)

## 1. Standards & Open-Source Reference
- **Standards:** Brakeman SAST ruleset, Official Ruby on Rails Security Guide, OWASP Ruby on Rails Cheat Sheet.
- **Focus:** Auditing Rails controllers, ActiveRecord queries, ERB views, and background workers (Sidekiq).

## 2. Rapid Discovery Patterns
- Search for `params.permit!`, `.constantize`, `.public_send(`, `.send(`, `render inline:`, `.html_safe`, `raw(`, `Kernel.open(`, `YAML.load(`.

## 3. Technical Audit Checklist
1. **Strong Parameters Enforcement:** Never call `params.permit!` or include `role`, `admin`, or `organization_id` in standard `params.require(:user).permit(...)` lists.
2. **ActiveRecord SQL Interpolation:** Never use Ruby string interpolation `"name = '#{params[:name]}'"` inside `.where()`, `.order()`, `.pluck()`, or `.find_by_sql()`; use hash conditions `.where(name: params[:name])` or placeholder arrays `.where("name = ?", params[:name])`.
3. **Dynamic Class / Method Dispatch (`constantize` & `send`):** Never call `params[:type].constantize` or `obj.send(params[:action])` directly on user input; map allowed string keys through a frozen Hash allowlist.
4. **Command Injection in `Kernel.open` / `IO.read`:** In Ruby, passing a string starting with `|` to `Kernel.open("|whoami")` executes a shell command! Always use `File.open` or `URI.open` with explicit scheme validation.
5. **ERB XSS & Session Serializer Hardening:** Avoid `.html_safe`, `raw()`, and `render inline:`; ensure `config.action_dispatch.cookies_serializer = :json` (never `:marshal` or `:hybrid`).

## 4. Vulnerable vs. Hardened Pattern
```ruby
# ❌ VULNERABLE: String interpolation in ActiveRecord & dynamic constantize
users = User.where("email = '#{params[:email]}'")
klass = params[:report_type].classify.constantize

# ✅ HARDENED: Bound parameters & explicit constant allowlist
users = User.where(email: params[:email].to_s)
REPORT_TYPES = { "daily" => DailyReport, "monthly" => MonthlyReport }.freeze
klass = REPORT_TYPES.fetch(params[:report_type])
```
