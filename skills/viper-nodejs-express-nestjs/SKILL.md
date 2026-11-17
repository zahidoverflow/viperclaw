---
name: viper-nodejs-express-nestjs
description: Node.js, Express, NestJS & Fastify Security Auditor. Reviews Guard/Pipe ordering, prototype pollution, trust proxy spoofing, child_process sinks, and event-loop ReDoS.
---

# ViperClaw Skill 39: Node.js, Express, NestJS & Fastify Security Auditor (`viper-nodejs-express-nestjs`)

## 1. Standards & Open-Source Reference
- **Standards:** NodeJS Security Cheat Sheet (OWASP), Semgrep `p/nodejs` & `p/typescript`, eslint-plugin-security.
- **Focus:** Auditing Express, NestJS, Fastify, and Koa backend applications.

## 2. Rapid Discovery Patterns
- Search for `@Public()`, `UseGuards`, `ValidationPipe`, `app.set('trust proxy'`, `Object.assign`, `lodash.merge`, `child_process`, `vm.runInNewContext`.

## 3. Technical Audit Checklist
1. **NestJS Global ValidationPipe & Guard Coverage:** Ensure `new ValidationPipe({ whitelist: true, forbidNonWhitelisted: true, transform: true })` is registered globally, and audit every `@Public()` decorator to ensure sensitive controllers are not inadvertently exposed.
2. **Prototype Pollution & Object Merging:** Audit recursive merge functions, query parsers (`qs` depth/allowPrototypes), and dynamic property assignments (`obj[userKey][subKey] = val`); use `Object.create(null)` or `Map` for user-keyed dictionaries.
3. **`trust proxy` & Client IP Spoofing:** Verify `app.set("trust proxy", ...)` is configured with the exact hop count or CIDR of the upstream load balancer so rate limiters and audit logs cannot be bypassed via forged `X-Forwarded-For` headers.
4. **Subprocess & VM Sandbox Sinks:** Replace `child_process.exec(cmd)` with `execFile(bin, args, { shell: false })`, and never use Node's built-in `vm` module to run untrusted code.
5. **Path Traversal in Static & Download Routes:** When serving files via `res.sendFile` or `fs.createReadStream`, use `path.resolve(ROOT_DIR, userPath)` and verify `resolved.startsWith(ROOT_DIR + path.sep)`.

## 4. Vulnerable vs. Hardened Pattern
```typescript
// ❌ VULNERABLE: NestJS DTO without whitelist allows mass-assigning role
app.useGlobalPipes(new ValidationPipe());

// ✅ HARDENED: Strips unknown properties and rejects unexpected fields
app.useGlobalPipes(new ValidationPipe({
  whitelist: true,
  forbidNonWhitelisted: true,
  transform: true,
}));
```
