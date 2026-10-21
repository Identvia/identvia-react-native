/** Core against a REAL Identvia (stage 4). IDENTVIA_LIVE_STATE=/tmp/live-state.json npx vitest run -c vitest.live.config.ts */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createHash, webcrypto } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import { IdentviaNativeClient, type SecureStorageAdapter } from '../src/client';
import { webCryptoProvider, type CryptoProvider } from '../src/crypto';

const P = process.env.IDENTVIA_LIVE_STATE;
const S = P ? JSON.parse(readFileSync(P, 'utf8')) : null;
const helper = new URL('../../tools/live/helper.php', import.meta.url).pathname;
const hermesLike: CryptoProvider = { getRandomBytes: (n) => webcrypto.getRandomValues(new Uint8Array(n)), sha256: async (s) => new Uint8Array(createHash('sha256').update(s).digest()) };
const mem = (): SecureStorageAdapter & { m: Map<string, string> } => { const m = new Map<string, string>(); return { m, getItem: async (k) => m.get(k) ?? null, setItem: async (k, v) => { m.set(k, v); }, deleteItem: async (k) => { m.delete(k); } }; };

describe.skipIf(!S)('live', () => {
  for (const [name, crypto] of [['Web Crypto (signature verified)', webCryptoProvider(webcrypto as unknown as Crypto)], ['Hermes-like (no SubtleCrypto)', hermesLike]] as const) {
    it(`sign-in, refresh rotation, userinfo, sign-out: ${name}`, async () => {
      const storage = mem();
      const c = new IdentviaNativeClient({ issuer: S.base, clientId: S.publicClientId, redirectUri: S.publicRedirect, crypto, storage, refreshLeewaySec: 10_000,
        authSession: { open: async (url, ru) => url.includes('/oauth/logout') ? { type: 'success', url: ru } : { type: 'success', url: execFileSync('php', [helper, 'browse', P!, url], { encoding: 'utf8' }).trim() } } });
      const s = await c.signIn();
      expect(s.user.email).toBe(S.userEmail);
      const rt1 = [...storage.m.entries()].find(([k]) => k.endsWith('.rt'))![1];
      await c.getAccessToken();
      const rt2 = [...storage.m.entries()].find(([k]) => k.endsWith('.rt'))![1];
      expect(rt2).not.toBe(rt1);
      expect((await c.userinfo()).sub).toBe(s.user.sub);
      await c.signOut();
      expect(storage.m.size).toBe(0);
    });
  }
});
