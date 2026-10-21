import { describe, expect, it, vi } from 'vitest';

vi.mock('expo-web-browser', () => ({
  openAuthSessionAsync: vi.fn(async (_u: string, ru: string) => ({ type: 'success', url: ru + '?code=c&state=s' })),
  maybeCompleteAuthSession: vi.fn(),
}));
vi.mock('expo-secure-store', () => {
  const m = new Map<string, string>();
  return {
    AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY: 'AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY',
    getItemAsync: vi.fn(async (k: string) => m.get(k) ?? null),
    setItemAsync: vi.fn(async (k: string, v: string) => { m.set(k, v); }),
    deleteItemAsync: vi.fn(async (k: string) => { m.delete(k); }),
  };
});
vi.mock('expo-crypto', async () => {
  const { createHash, randomBytes } = await import('node:crypto');
  return {
    CryptoDigestAlgorithm: { SHA256: 'SHA-256' }, CryptoEncoding: { BASE64: 'base64' },
    getRandomBytes: (n: number) => new Uint8Array(randomBytes(n)),
    digestStringAsync: async (_a: string, s: string) => createHash('sha256').update(s).digest('base64'),
  };
});

describe('Expo adapters', () => {
  it('use ASWebAuthenticationSession/Custom Tabs via expo-web-browser, Keychain via SecureStore, expo-crypto', async () => {
    const { expoAuthSession, expoSecureStorage, expoCrypto } = await import('../src/expo');
    const WebBrowser = await import('expo-web-browser');
    const SecureStore = await import('expo-secure-store');
    const r = await expoAuthSession.open('https://id.identvia.com/oauth/authorize?x', 'com.example.app:/cb', { ephemeral: true });
    expect(r).toEqual({ type: 'success', url: 'com.example.app:/cb?code=c&state=s' });
    expect(WebBrowser.openAuthSessionAsync).toHaveBeenCalledWith('https://id.identvia.com/oauth/authorize?x', 'com.example.app:/cb', { preferEphemeralSession: true, showInRecents: false });
    await expoSecureStorage.setItem('k', 'v');
    expect(await expoSecureStorage.getItem('k')).toBe('v');
    expect(SecureStore.setItemAsync).toHaveBeenCalledWith('k', 'v', { keychainAccessible: 'AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY' });
    const { codeChallenge } = await import('../src/crypto');
    expect(await codeChallenge(expoCrypto, 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
    expect(expoCrypto.getRandomBytes(32).length).toBe(32);
  });
});
