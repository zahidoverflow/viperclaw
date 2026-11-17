---
name: viper-java-spring-audit
description: Java, Spring Boot & Spring Security Auditor (modeled on FindSecBugs & Semgrep Java). Reviews Actuator exposure, SpEL injection, @PreAuthorize, Jackson typing, and JNDI/JDBC.
---

# ViperClaw Skill 42: Java, Spring Boot & Spring Security Auditor (`viper-java-spring-audit`)

## 1. Standards & Open-Source Reference
- **Standards:** FindSecBugs, OWASP Java Security Cheat Sheet, Semgrep `p/java` & `p/spring`.
- **Focus:** Auditing Spring Boot, Spring Security, Hibernate/JPA, Jackson, and JDBC configurations.

## 2. Rapid Discovery Patterns
- Search for `management.endpoints.web.exposure.include`, `SpelExpressionParser`, `@Query(`, `enableDefaultTyping`, `DriverManager.getConnection`, `ObjectInputStream`.

## 3. Technical Audit Checklist
1. **Spring Boot Actuator Hardening:** Ensure `application.properties` / `application.yml` does not set `management.endpoints.web.exposure.include=*` in production (which exposes `/actuator/env`, `/actuator/heapdump`, and `/actuator/mappings`). Expose only `health` and `info` on an isolated management port.
2. **SpEL (Spring Expression Language) Injection:** Never pass user-controlled strings into `SpelExpressionParser.parseExpression()`; if expressions are required, use `SimpleEvaluationContext.forReadOnlyDataBinding()` instead of `StandardEvaluationContext`.
3. **JPA / Hibernate HQL Parameterization:** In `@Query` annotations and `EntityManager.createQuery()`, always use `:namedParam` or `?1` positional binding—never string concatenation.
4. **Jackson Polymorphic Deserialization & Mass Assignment:** Never enable global `ObjectMapper.enableDefaultTyping()`; use `@JsonTypeInfo` with explicit `@JsonSubTypes` allowlists, and bind `@RequestBody` to dedicated Record/DTO classes rather than `@Entity` models.
5. **JDBC Connection String & JNDI Safety:** Prevent user-controlled parameters in JDBC URLs (`autoDeserialize=true`, `allowLoadLocalInfile=true`, H2 `INIT=RUNSCRIPT`) and disable remote JNDI class loading.

## 4. Vulnerable vs. Hardened Pattern
```java
// ❌ VULNERABLE: StandardEvaluationContext allows arbitrary class instantiation & RCE
ExpressionParser parser = new SpelExpressionParser();
Object val = parser.parseExpression(userFilter).getValue(new StandardEvaluationContext(rootObj));

// ✅ HARDENED: Read-only data binding context blocks method calls and type references
EvaluationContext safeCtx = SimpleEvaluationContext.forReadOnlyDataBinding().build();
Object val = parser.parseExpression(allowlistedField).getValue(safeCtx, rootObj);
```
