---
name: viper-mobile-api-config
description: Mobile App Static Configuration & API Security Auditor (modeled on OWASP MASVS & MobSF). Reviews AndroidManifest.xml, Network Security Config, iOS Info.plist, and deeplink handlers.
---

# ViperClaw Skill 29: Mobile App Configuration & MASVS Auditor (`viper-mobile-api-config`)

## Overview
Audits Android (`AndroidManifest.xml`, `network_security_config.xml`, Kotlin/Java) and iOS (`Info.plist`, Swift) source/configurations against the OWASP Mobile Application Security Verification Standard (MASVS).

## Audit Checklist
1. **Exported Components & Deeplinks:** Review `android:exported="true"` activities, services, broadcast receivers, and custom URL schemes / App Links to ensure untrusted intents cannot access internal WebViews or local files.
2. **Transport & Cleartext Security:** Confirm `cleartextTrafficPermitted="false"` on Android and `NSAllowsArbitraryLoads = false` in iOS App Transport Security (ATS).
3. **WebView & Local Storage Hardening:** Disable `setAllowFileAccessFromFileURLs`, audit `addJavascriptInterface` bridges, and store tokens in Android Keystore / iOS Keychain rather than plaintext `SharedPreferences`/`NSUserDefaults`.
