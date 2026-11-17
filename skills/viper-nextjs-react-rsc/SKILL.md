---
name: viper-nextjs-react-rsc
description: Next.js App Router, React Server Components (RSC) & Server Actions Security Auditor. Reviews 'use server' authorization, NEXT_PUBLIC_ leaks, and prop serialization.
---

# ViperClaw Skill 37: Next.js, React Server Components & Server Actions Auditor (`viper-nextjs-react-rsc`)

## 1. Standards & Open-Source Reference
- **Standards:** Next.js Data Security Guide, OWASP Top 10 (A01 Broken Access Control, A04 Insecure Design), Semgrep `p/nextjs` & `p/react`.
- **Focus:** Auditing Next.js 13/14/15+ App Router, `"use server"` Server Actions, React Server Components (RSC), and `middleware.ts`.

## 2. Rapid Discovery Patterns
- Search for `"use server"`, `'use server'`, `NEXT_PUBLIC_`, `dangerouslySetInnerHTML`, `headers()`, `cookies()`, `NextResponse.next()`.

## 3. Technical Audit Checklist
1. **Server Action Authentication & Authorization:** Every exported `"use server"` function is a public HTTP `POST` endpoint; verify that *each* Server Action independently authenticates the session and validates input with `zod` before mutating data.
2. **RSC Prop Serialization Tainting (`experimental_taintObjectReference`):** Never pass full ORM database objects (`user`) directly from a Server Component into a `"use client"` component, as all serialized props are sent in the RSC flight payload to the browser. Use DTO mappers or `server-only` modules.
3. **`NEXT_PUBLIC_` Environment Variable Hygiene:** Audit `.env*` and `next.config.js` to confirm no private API keys, database URLs, or signing secrets use the `NEXT_PUBLIC_` prefix.
4. **Middleware Route Coverage (`matcher`):** Do not rely solely on `middleware.ts` path matchers for authentication; enforce authorization inside the Data Access Layer (DAL) on every query and mutation.
5. **Open Redirect & `next/image` SSRF Prevention:** Restrict `images.remotePatterns` in `next.config.js` to specific trusted hostnames/paths and validate `redirect()` targets against a relative-path check.

## 4. Vulnerable vs. Hardened Pattern
```typescript
// ❌ VULNERABLE: Server Action trusts client-supplied userId without session check
"use server";
export async function updateEmail(userId: string, newEmail: string) {
  await db.user.update({ where: { id: userId }, data: { email: newEmail } });
}

// ✅ HARDENED: Authenticates caller & validates input schema inside Server Action
"use server";
import { z } from "zod";
const EmailSchema = z.object({ newEmail: z.string().email() });
export async function updateEmail(formData: unknown) {
  const session = await requireVerifiedSession();
  const { newEmail } = EmailSchema.parse(formData);
  await db.user.update({ where: { id: session.user.id }, data: { email: newEmail } });
}
```
