---
name: viper-go-service-audit
description: Go (Golang) Microservice & Concurrency Security Auditor (modeled on Trail of Bits Go & gosec). Reviews http.Server timeouts, goroutine races, filepath.Clean, and SQL/TLS safety.
---

# ViperClaw Skill 40: Go (Golang) Microservice & Concurrency Auditor (`viper-go-service-audit`)

## 1. Standards & Open-Source Reference
- **Standards:** `securego/gosec`, Trail of Bits Go Semgrep rules (`p/golang`), Go Standard Library Security practices.
- **Focus:** Auditing Go HTTP services, database layers, concurrency primitives, and filesystem handlers.

## 2. Rapid Discovery Patterns
- Search for `http.ListenAndServe(`, `ReadHeaderTimeout`, `InsecureSkipVerify`, `math/rand`, `filepath.Join`, `fmt.Sprintf("SELECT`, `go func(`.

## 3. Technical Audit Checklist
1. **HTTP Server Slowloris & Timeout Hardening:** Never call `http.ListenAndServe(addr, handler)` directly in production; instantiate `&http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}`.
2. **Goroutine Leak & Data Race Prevention:** Ensure every spawned goroutine binds to `ctx.Done()` with bounded channels, avoid capturing loop variables by reference in older Go versions, and verify `go test -race ./...` passes cleanly.
3. **Filesystem Traversal (`os.Root` / Prefix Verification):** Note that `filepath.Join(baseDir, userPath)` calls `filepath.Clean` and **strips** `baseDir` if `userPath` resolves to `../../etc/passwd`! Always verify `strings.HasPrefix(cleanTarget, cleanBase + string(os.PathSeparator))` or use Go 1.24+ `os.OpenRoot(baseDir)`.
4. **Cryptographic RNG & TLS Verification:** Replace `math/rand` with `crypto/rand` for all security-sensitive values, and forbid `tls.Config{InsecureSkipVerify: true}` and TLS < 1.2.
5. **Defer & Transaction Rollback Safety:** Ensure `defer rows.Close()` and `defer tx.Rollback()` are called immediately after error checks so database connections are never leaked on early returns.

## 4. Vulnerable vs. Hardened Pattern
```go
// ❌ VULNERABLE: Default http.ListenAndServe has zero timeouts (Slowloris DoS)
log.Fatal(http.ListenAndServe(":8080", mux))

// ✅ HARDENED: Explicit timeouts and header caps
srv := &http.Server{
    Addr:              ":8080",
    Handler:           mux,
    ReadHeaderTimeout: 5 * time.Second,
    ReadTimeout:       15 * time.Second,
    WriteTimeout:      30 * time.Second,
    IdleTimeout:       60 * time.Second,
}
log.Fatal(srv.ListenAndServe())
```
