---
name: viper-browser-extension-mv3
description: Chrome/Firefox Browser Extension (Manifest V3) Security Auditor. Reviews externally_connectable, content-script postMessage origins, web_accessible_resources, and host permissions.
---

# ViperClaw Skill 57: Browser Extension (Manifest V3) Security Auditor (`viper-browser-extension-mv3`)

## 1. Standards & Open-Source Reference
- **Standards:** Chrome Extension Manifest V3 Security Best Practices, Mozilla Add-on Security Guidelines.
- **Focus:** Auditing `manifest.json`, service workers (`background.js`), content scripts, and extension popup/options pages.

## 2. Rapid Discovery Patterns
- Search for `"manifest_version": 3`, `externally_connectable`, `web_accessible_resources`, `chrome.runtime.onMessageExternal`, `chrome.tabs.executeScript`, `window.addEventListener("message"`.

## 3. Technical Audit Checklist
1. **Service Worker Message Sender Validation (`onMessage` & `onMessageExternal`):** Any compromised web page where a content script runs can send messages via `chrome.runtime.sendMessage`! Inside the background service worker, always verify `sender.id === chrome.runtime.id` and validate `sender.url` / `sender.origin` before performing privileged `fetch`, cookie, or storage actions.
2. **Content Script `window.postMessage` Isolation:** Content scripts share the DOM with the untrusted host webpage. Never trust `window.addEventListener("message", (e) => ...)` without checking `e.source === window` and `e.origin === expectedOrigin`, and never pass message data into `innerHTML` or `chrome.runtime.sendMessage` unchecked.
3. **`externally_connectable` & `web_accessible_resources` Minimization:** Avoid wildcard match patterns (`*://*.example.com/*` or `<all_urls>`) in `externally_connectable.matches` and `web_accessible_resources`, and enable `use_dynamic_url: true` to prevent extension fingerprinting and CSRF.
4. **Least-Privilege Permissions (`activeTab` over `<all_urls>`):** Prefer `activeTab` over broad `host_permissions: ["<all_urls>"]`, and never store plaintext user passwords or long-lived tokens in unencrypted `chrome.storage.local` accessible to content scripts (use `chrome.storage.session` with `setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' })`).
5. **Extension Page DOM XSS Prevention:** Even with MV3's `script-src 'self'` CSP, assigning untrusted data to `innerHTML` inside `popup.html` or `options.html` can abuse DOM gadgets or leak `chrome.*` storage APIs; always use `textContent`.

## 4. Vulnerable vs. Hardened Pattern
```javascript
// ❌ VULNERABLE: Background worker executes privileged cross-origin fetch for any content script
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "API_FETCH") {
    fetch(msg.url, { credentials: "include" }).then(r => r.text()).then(sendResponse);
    return true;
  }
});

// ✅ HARDENED: Restricts sender to extension's own trusted popup/options UI & pinned API host
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  const trustedPrefix = `chrome-extension://${chrome.runtime.id}/`;
  if (!sender.url || !sender.url.startsWith(trustedPrefix)) return false;
  if (msg.type === "API_FETCH" && new URL(msg.url).origin === "https://api.example.com") {
    fetch(msg.url, { credentials: "include" }).then(r => r.json()).then(sendResponse);
    return true;
  }
});
```
