import * as WebBrowser from 'expo-web-browser';
import * as SecureStore from 'expo-secure-store';
import * as ExpoCrypto from 'expo-crypto';
import { base64Decode } from './encoding';
import type { CryptoProvider } from './crypto';
import type { AuthSessionAdapter, SecureStorageAdapter } from './client';

/**
 * System-browser auth session via expo-web-browser:
 * iOS → ASWebAuthenticationSession, Android → Chrome Custom Tabs (falls back to the default browser). Never a WebView.
 */
export const expoAuthSession: AuthSessionAdapter = {
  async open(url, redirectUri, { ephemeral }) {
    const r = await WebBrowser.openAuthSessionAsync(url, redirectUri, { preferEphemeralSession: ephemeral, showInRecents: false });
    if (r.type === 'success') return { type: 'success', url: r.url };
    return { type: r.type === 'locked' ? 'locked' : r.type === 'dismiss' ? 'dismiss' : 'cancel' };
  },
};

/** Keychain (iOS, this device only, after first unlock) / Android Keystore-encrypted storage via expo-secure-store. */
export const expoSecureStorage: SecureStorageAdapter = {
  getItem: (k) => SecureStore.getItemAsync(k, { keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY }),
  setItem: (k, v) => SecureStore.setItemAsync(k, v, { keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY }),
  deleteItem: (k) => SecureStore.deleteItemAsync(k, { keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY }),
};

/** CSPRNG + SHA-256 from expo-crypto. Adds Web Crypto `subtle` (signature checks) when a polyfill such as react-native-quick-crypto installed one. */
export const expoCrypto: CryptoProvider = {
  getRandomBytes: (n) => ExpoCrypto.getRandomBytes(n),
  sha256: async (s) => base64Decode(await ExpoCrypto.digestStringAsync(ExpoCrypto.CryptoDigestAlgorithm.SHA256, s, { encoding: ExpoCrypto.CryptoEncoding.BASE64 })),
  get subtle() { return (globalThis as { crypto?: Crypto }).crypto?.subtle; },
};

/** Call once at app start on Android/web so a pending auth session completes (expo-web-browser requirement on web). */
export function maybeCompleteAuthSession(): void { WebBrowser.maybeCompleteAuthSession(); }
