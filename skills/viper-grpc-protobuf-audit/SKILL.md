---
name: viper-grpc-protobuf-audit
description: gRPC, Protobuf & Internal RPC Security Auditor. Reviews mTLS transport enforcement, unary/streaming auth interceptors, MaxRecvMsgSize caps, and gRPC server reflection.
---

# ViperClaw Skill 45: gRPC, Protobuf & Internal RPC Security Auditor (`viper-grpc-protobuf-audit`)

## 1. Standards & Open-Source Reference
- **Standards:** OWASP gRPC Security Cheat Sheet, Semgrep gRPC rules, Protobuf `protovalidate` / `protoc-gen-validate`.
- **Focus:** Auditing gRPC servers/clients across Go, Rust (`tonic`), Python (`grpcio`), Node.js, and Java.

## 2. Rapid Discovery Patterns
- Search for `grpc.WithInsecure()`, `insecure.NewCredentials()`, `grpc.insecure_channel`, `reflection.Register(`, `UnaryInterceptor`, `StreamInterceptor`, `MaxRecvMsgSize`.

## 3. Technical Audit Checklist
1. **Mutual TLS (mTLS) Transport Security:** Forbid `grpc.WithInsecure()`, `insecure.NewCredentials()`, and `grpc.insecure_channel` in production; require TLS 1.3 or SPIFFE mTLS credentials for all service-to-service channels.
2. **Both Unary & Stream Auth Interceptors:** A common flaw is registering a `UnaryInterceptor` for authentication while forgetting `StreamInterceptor`, leaving bidirectional or server-streaming RPCs unauthenticated. Always register both!
3. **Protobuf Field Validation (`protovalidate`):** Protobuf wire types enforce data types (`int64`, `string`) but **do not** validate bounds, UUID formats, or negative numbers; enforce `bufbuild/protovalidate` rules in the server interceptor.
4. **Message Size & Concurrency Quotas:** Configure explicit `MaxRecvMsgSize` (e.g., 4 MB), `MaxSendMsgSize`, and `MaxConcurrentStreams` to prevent memory exhaustion DoS.
5. **Disable Unauthenticated gRPC Reflection & Channelz:** Disable `reflection.Register(s)` and `channelz` in production environments so internal service definitions and method names are not publicly enumerable.

## 4. Vulnerable vs. Hardened Pattern
```go
// ❌ VULNERABLE: Only UnaryInterceptor registered; streaming RPCs bypass auth & reflection enabled
s := grpc.NewServer(grpc.UnaryInterceptor(authUnaryInterceptor))
reflection.Register(s)

// ✅ HARDENED: TLS credentials + both Unary and Stream auth interceptors + message size cap
s := grpc.NewServer(
    grpc.Creds(tlsCreds),
    grpc.MaxRecvMsgSize(4 * 1024 * 1024),
    grpc.UnaryInterceptor(authUnaryInterceptor),
    grpc.StreamInterceptor(authStreamInterceptor),
)
```
