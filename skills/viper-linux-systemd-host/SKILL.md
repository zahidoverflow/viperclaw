---
name: viper-linux-systemd-host
description: Linux Host, Systemd Unit, SUID & Seccomp Hardening Auditor (modeled on Lynis & CIS Linux Benchmarks). Reviews systemd sandboxing, sudoers, sysctl, and SSH configs.
---

# ViperClaw Skill 50: Linux Host, Systemd & Kernel Hardening Auditor (`viper-linux-systemd-host`)

## 1. Standards & Open-Source Reference
- **Standards:** CIS Distribution Independent Linux Benchmark, `CISOfy/lynis`, `systemd-analyze security`.
- **Focus:** Auditing Linux server configurations, `systemd` service units, `/etc/sudoers`, `/etc/ssh/sshd_config`, and `sysctl` parameters.

## 2. Rapid Discovery Patterns
- Search `*.service` files for `User=root`, missing `ProtectSystem=`, `NoNewPrivileges=`, `PrivateTmp=`.
- Search `sudoers` / provisioning scripts for `NOPASSWD: ALL`, `chmod 4755`, `chmod 777`.

## 3. Technical Audit Checklist
1. **Systemd Service Unit Sandboxing (`systemd-analyze security`):** Every production `.service` unit should run as an unprivileged `User=` / `DynamicUser=yes` and enforce `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `PrivateTmp=yes`, `PrivateDevices=yes`, `ProtectKernelTunables=yes`, and `CapabilityBoundingSet=`.
2. **Sudoers & SUID/SGID Hygiene:** Never grant `(ALL) NOPASSWD: ALL` or allow wildcards `*` in `sudoers` commands (`sudo /bin/chown *` allows `/etc/shadow` takeover via `--reference`). Audit SUID/SGID binaries (`find / -perm /6000`).
3. **SSH Daemon (`sshd_config`) Hardening:** Enforce `PermitRootLogin no`, `PasswordAuthentication no`, `PubkeyAuthentication yes`, `KbdInteractiveAuthentication no`, `X11Forwarding no`, and `MaxAuthTries 3`.
4. **Kernel & Network `sysctl` Hardening:** Verify `kernel.kptr_restrict = 2`, `kernel.dmesg_restrict = 1`, `kernel.yama.ptrace_scope = 2`, `fs.protected_hardlinks = 1`, `fs.protected_symlinks = 1`, and `net.ipv4.conf.all.rp_filter = 1`.
5. **Cron & Systemd Timer Path Ownership:** Confirm all scripts executed by root cron jobs or systemd timers are owned by `root:root` with mode `0755`/`0644` and located in non-world-writable directories.

## 4. Vulnerable vs. Hardened Pattern
```ini
# ❌ VULNERABLE: Runs as root with unrestricted filesystem & capability access
[Service]
ExecStart=/usr/local/bin/app-worker

# ✅ HARDENED: Isolated unprivileged systemd service sandbox
[Service]
ExecStart=/usr/local/bin/app-worker
DynamicUser=yes
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
CapabilityBoundingSet=
SystemCallFilter=@system-service
```
