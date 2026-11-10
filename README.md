# @identvia/react-native

[![npm](https://img.shields.io/npm/v/@identvia/react-native)](https://www.npmjs.com/package/@identvia/react-native)
[![CI](https://github.com/Identvia/identvia-react-native/actions/workflows/ci.yml/badge.svg)](https://github.com/Identvia/identvia-react-native/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/Identvia/identvia-react-native/blob/main/LICENSE)

Sign in with Identvia for React Native and Expo.

* **System browser only:** ASWebAuthenticationSession on iOS and Chrome Custom Tabs on Android, through `expo-web-browser`. The SDK never uses an embedded WebView, as RFC 8252 requires.
* **Authorization Code + PKCE S256**, with `state`, `nonce` and the RFC 9207 `iss` check. The callback must come back to your exact redirect URI.
* **Public client only:** the constructor refuses a `clientSecret`.
* **Secure storage:** iOS Keychain (`AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY`) and the Android Keystore, through `expo-secure-store`. The refresh token is kept in its own item.
* **Refresh-token rotation** is single-flight. If Identvia detects a reused refresh token, the user is signed out.
* **ID token checks:** `iss`, `aud`, `azp`, `exp`, `iat`, `nonce`, `max_age` and `at_hash`, with only RS256/ES256 accepted. The RS256/ES256 **signature** is verified when Web Crypto `subtle` is available, for example after installing [`react-native-quick-crypto`](https://github.com/margelo/react-native-quick-crypto). Without it, the SDK relies on the direct TLS connection to the token endpoint, which OIDC Core §3.1.3.7 step 6 allows. Set `idTokenSignature: 'required'` to insist on signature checks.
* An **Expo config plugin** registers your redirect: a URL scheme for a custom scheme, or associated domains plus a verified App Link for https.
* It works on Hermes and doesn't depend on React Native's incomplete `URL` global.

## Install

```bash
npx expo install @identvia/react-native expo-web-browser expo-secure-store expo-crypto
```

`app.json`:

```json
{ "expo": { "scheme": "com.example.notes",
  "plugins": [["@identvia/react-native", { "redirectUri": "com.example.notes:/oauth/identvia" }], "expo-secure-store"] } }
```

## Use

```tsx
import { IdentviaProvider, SignInWithIdentvia, useIdentvia } from '@identvia/react-native';

export default function App() {
  return (
    <IdentviaProvider clientId="oid_…" redirectUri="com.example.notes:/oauth/identvia" scopes={['email', 'profile', 'offline_access']}>
      <Screen />
    </IdentviaProvider>
  );
}

function Screen() {
  const { user, signOut, getAccessToken } = useIdentvia();
  return user ? <Button title="Sign out" onPress={() => signOut()} /> : <SignInWithIdentvia theme="dark" />;
}
```

Store `user.sub` (pairwise: stable for your app, different in every other app), not the email.

### Redirect URIs

| Kind | Example | Notes |
|---|---|---|
| Private-use scheme (recommended on iOS) | `com.example.notes:/oauth/identvia` | Reverse-domain form only (RFC 8252 §7.1). `myapp://` is rejected. |
| Universal Link / App Link | `https://notes.example.com/identvia/callback` | You must host `apple-app-site-association` and `assetlinks.json`. iOS only intercepts https callbacks in ASWebAuthenticationSession on iOS 17.4+. |

> **Server note:** Identvia's developer portal only accepts https redirect URIs (plus `http://localhost` in Development). Private-use schemes are accepted for **native** clients registered through Dynamic Client Registration. Until the portal gets a "Native app" type, use an https App Link or register through DCR.

### Without Expo

Import the platform-neutral core from `@identvia/react-native/core`. Then implement `AuthSessionAdapter` (for example with `react-native-app-auth` or `react-native-inappbrowser-reborn`'s `openAuth`), `SecureStorageAdapter` (for example `react-native-keychain`) and `CryptoProvider`.

### Rich Authorization Requests (requires server 2026-10-21_5+)

```ts
await signIn({ authorizationDetails: [{ type: 'agent_task', description: 'Order groceries under $80' }] });
```

Token exchange and CIBA are server-side flows that need a client secret, so they live in `@identvia/js/server`, not in mobile SDKs.

## Development

```bash
npm install --legacy-peer-deps && npm run build && npm test
IDENTVIA_LIVE_STATE=/tmp/live-state.json npx vitest run -c vitest.live.config.ts   # against a real Identvia
```

The example Expo app is in `example/`.

Docs: https://identvia.com · MIT licensed.
