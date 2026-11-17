---
name: viper-electron-tauri-desktop
description: Electron & Tauri Desktop Application Security Auditor (modeled on Electronegativity & Doyensec checklists). Reviews nodeIntegration, contextIsolation, IPC senders, and shell.openExternal.
---

# ViperClaw Skill 56: Electron & Tauri Desktop Application Auditor (`viper-electron-tauri-desktop`)

## 1. Standards & Open-Source Reference
- **Standards:** Doyensec `electronegativity`, Official Electron Security Checklist, Tauri v2 Security & Capabilities Guide.
- **Focus:** Auditing cross-platform desktop applications built with Electron or Tauri (Rust + WebView).

## 2. Rapid Discovery Patterns
- **Electron:** `nodeIntegration`, `contextIsolation`, `sandbox:`, `webSecurity`, `ipcMain.handle`, `shell.openExternal`, `will-navigate`.
- **Tauri:** `tauri.conf.json`, `capabilities`, `allowlist`, `#[tauri::command]`, `danger_disable_asset_csp_modification`.

## 3. Technical Audit Checklist
1. **Electron BrowserWindow WebPreferences Hardening:** Every `BrowserWindow` and `WebContentsView` must enforce `nodeIntegration: false`, `contextIsolation: true`, `sandbox: true`, `webSecurity: true`, and `allowRunningInsecureContent: false`.
2. **Preload `contextBridge` Minimization & IPC Sender Verification:** Never expose raw `ipcRenderer` via `contextBridge.exposeInMainWorld`; expose narrow, typed wrapper functions, and inside every `ipcMain.handle` listener validate `event.senderFrame.url` against your trusted local origin.
3. **`shell.openExternal` Protocol Allowlisting:** Passing untrusted URLs (`file://`, `smb://`, `ms-msdt:`, `javascript:`) to `shell.openExternal(url)` causes instant desktop RCE! Parse with `new URL(url)` and allow only `https:` (and `mailto:` if needed).
4. **Navigation & New-Window Lockdown:** Attach `contents.on("will-navigate")` and `contents.setWindowOpenHandler()` to block navigation away from the application's bundled origin.
5. **Tauri v2 Capabilities & CSP Hardening:** In Tauri `tauri.conf.json` and `capabilities/*.json`, enforce a strict `csp`, scope `fs` permissions to specific `$APPDATA` subdirectories (no `$HOME/**`), and validate all arguments inside `#[tauri::command]` Rust functions.

## 4. Vulnerable vs. Hardened Pattern
```typescript
// ❌ VULNERABLE: Allows arbitrary protocol execution (file://, smb://, ms-msdt:)
ipcMain.handle("open-link", (_event, targetUrl: string) => {
  return shell.openExternal(targetUrl);
});

// ✅ HARDENED: Validates sender frame origin & enforces strict https:// protocol allowlist
ipcMain.handle("open-link", (event, targetUrl: string) => {
  const senderUrl = new URL(event.senderFrame.url);
  if (senderUrl.protocol !== "app:") throw new Error("Untrusted IPC sender");
  const parsed = new URL(targetUrl);
  if (parsed.protocol !== "https:") throw new Error("Blocked non-HTTPS external URL");
  return shell.openExternal(parsed.toString());
});
```
