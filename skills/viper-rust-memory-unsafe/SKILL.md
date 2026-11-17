---
name: viper-rust-memory-unsafe
description: Rust 'unsafe', FFI, Async & Integer Safety Auditor (modeled on RustSec, Rudra & Clippy security lints). Reviews unsafe invariants, Send/Sync soundness, and release-mode overflow.
---

# ViperClaw Skill 41: Rust Memory, `unsafe` & Integer Safety Auditor (`viper-rust-memory-unsafe`)

## 1. Standards & Open-Source Reference
- **Standards:** RustSec Advisory DB, Rudra (memory-safety analyzer), ANSSI Rust Secure Coding Guide, Clippy `undocumented_unsafe_blocks`.
- **Focus:** Auditing Rust systems code, Web/Axum/Actix services, FFI boundaries, and cryptographic crates.

## 2. Rapid Discovery Patterns
- Search for `unsafe `, `std::mem::transmute`, `from_raw_parts`, `set_len`, `as usize`, `unwrap()`, `unsafe impl Send`, `unsafe impl Sync`.

## 3. Technical Audit Checklist
1. **`unsafe` Invariant & `set_len` Auditing:** Audit every `unsafe` block to ensure pointer alignment, non-nullability, lifetime validity, and initialization invariants hold even if a caller-supplied closure panics (Rudra panic-safety pattern; never call `Vec::set_len` *before* initializing elements).
2. **Release-Mode Integer Overflow & Cast Truncation:** In Cargo `--release` builds, standard `+`, `*`, and `-` wrap silently by default! Use `.checked_add()`, `.saturating_mul()`, or `overflow-checks = true` in `Cargo.toml`, and use `usize::try_from(val)` instead of truncating `as` casts.
3. **Manual `Send` / `Sync` Soundness:** Audit every `unsafe impl Send` and `unsafe impl Sync` to confirm interior mutability (`UnsafeCell`, raw pointers) is protected by atomic operations or locks.
4. **DoS via `.unwrap()` / `.expect()` on Untrusted Input:** Never call `.unwrap()`, `.expect()`, or slice indexing `buf[idx]` on network-supplied inputs inside request handlers; use `.get(idx)` and propagate errors with `?`.
5. **FFI Boundary Null & Aliasing Safety:** Validate C pointers for `is_null()` before dereferencing, catch Rust panics with `std::panic::catch_unwind` before crossing `extern "C"` boundaries, and bound buffer lengths.

## 4. Vulnerable vs. Hardened Pattern
```rust
// ❌ VULNERABLE: wraps in release builds & panics on out-of-bounds slice
pub fn read_frame(buf: &[u8], offset: u32, len: u32) -> &[u8] {
    let end = (offset + len) as usize;
    &buf[offset as usize..end]
}

// ✅ HARDENED: Checked arithmetic and non-panicking slice lookup
pub fn read_frame(buf: &[u8], offset: u32, len: u32) -> Option<&[u8]> {
    let start = usize::try_from(offset).ok()?;
    let end = start.checked_add(usize::try_from(len).ok()?)?;
    buf.get(start..end)
}
```
