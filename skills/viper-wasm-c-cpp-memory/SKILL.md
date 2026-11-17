---
name: viper-wasm-c-cpp-memory
description: C, C++, JNI & WebAssembly Memory Safety Auditor (modeled on Trail of Bits C/C++ & Flawfinder). Reviews buffer bounds, integer overflows, UAF, format strings, and compiler hardening.
---

# ViperClaw Skill 62: C, C++, JNI & WebAssembly Memory Safety Auditor (`viper-wasm-c-cpp-memory`)

## 1. Standards & Open-Source Reference
- **Standards:** CERT C / C++ Coding Standard, CWE-119/125/787/416/190/134, OpenSSF Compiler Options Hardening Guide for C and C++.
- **Focus:** Auditing native C/C++ modules, Python/Node/Java native extensions (Cython, N-API, JNI), and WebAssembly (WASI) sandboxes.

## 2. Rapid Discovery Patterns
- Search for banned C functions: `strcpy`, `strcat`, `sprintf`, `vsprintf`, `gets`, `scanf("%s"`, `alloca(`, `memcpy(`, `realloc(`.
- Search `CMakeLists.txt` / `Makefile` for `-fstack-protector-strong`, `-D_FORTIFY_SOURCE=3`, `-fPIE`, `-Wl,-z,relro,-z,now`.

## 3. Technical Audit Checklist
1. **Eliminate Unbounded String & Buffer Copy Functions:** Replace `strcpy`, `strcat`, `sprintf`, and `gets` with bounded alternatives (`snprintf`, `strlcpy`, `std::string`, `std::span`), and verify that `memcpy(dst, src, n)` checks `n <= dst_capacity` before copying.
2. **Allocation Size Integer Overflow (`count * sizeof(T)`):** Computing `malloc(count * sizeof(Item))` when `count` is untrusted can overflow 32/64-bit integers, allocating a tiny buffer followed by a heap buffer overflow! Use `calloc(count, sizeof(Item))` or `__builtin_mul_overflow(count, sizeof(Item), &total)`.
3. **Format String & Signed/Unsigned Length Confusion:** Never pass a variable as the first format argument (`printf(user_msg)` / `syslog(LOG_INFO, user_msg)` -> use `"%s", user_msg`); never use signed `int` for buffer lengths where a negative value bypasses `if (len < MAX_SIZE)` and wraps to a huge `size_t`.
4. **Use-After-Free (UAF), Double-Free & `realloc` Pitfalls:** Never write `ptr = realloc(ptr, new_size)` directly (leaks or corrupts `ptr` on failure); use a temporary pointer, null out pointers after `free()`, and prefer C++ smart pointers (`std::unique_ptr`).
5. **Compiler & Linker Exploit Mitigations (OpenSSF Guide):** Enforce `-O2 -D_FORTIFY_SOURCE=3 -fstack-protector-strong -fstack-clash-protection -fPIE -pie -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack` in production builds and run AddressSanitizer + UndefinedBehaviorSanitizer (`-fsanitize=address,undefined`) in CI.

## 4. Vulnerable vs. Hardened Pattern
```c
// ❌ VULNERABLE: Signed length check bypass & integer overflow in malloc size
Item *alloc_items(int count) {
    if (count > 1024) return NULL; // Negative count bypasses check!
    return (Item *)malloc(count * sizeof(Item));
}

// ✅ HARDENED: Unsigned bounds check & overflow-safe calloc
Item *alloc_items(size_t count) {
    if (count == 0 || count > 1024) return NULL;
    return (Item *)calloc(count, sizeof(Item));
}
```
