# Changelog

## 0.1.1 (2026-10-21)

- Repository hygiene: `.gitignore` now excludes build output, packages, Expo prebuild folders and local live-test state. No code changes.

## 0.1.0 (2026-10-21)
* First release.
* `IdentviaNativeClient`: system-browser sign-in with PKCE S256, state, nonce and the iss check. Secure session storage, refresh rotation, userinfo, and sign-out with revocation and optional RP-initiated logout.
* Expo adapters: expo-web-browser, expo-secure-store and expo-crypto.
* `IdentviaProvider`, `useIdentvia` and `<SignInWithIdentvia/>`, which uses the brand colours, sizes and shapes of button.js.
* An Expo config plugin for custom-scheme or https (Universal Link / App Link) redirects.
* `authorization_details` (RFC 9396), which requires server 2026-10-21_5+.
