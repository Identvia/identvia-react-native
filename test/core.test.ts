import { describe, expect, it, vi } from 'vitest';
import { createHash, webcrypto } from 'node:crypto';
import { SignJWT, generateKeyPair } from 'jose';
import { IdentviaNativeClient, assertNativeRedirect, type AuthSessionAdapter, type SecureStorageAdapter } from '../src/client';
import { codeChallenge, webCryptoProvider, type CryptoProvider } from '../src/crypto';
import { CancelledError, ConfigurationError, InvalidStateError, TokenError, UnsupportedError, ValidationError, AuthorizationError } from '../src/errors';
import { parseUrl, withQuery } from '../src/url';
import { createFake, ISSUER } from './fake-identvia';

const REDIRECT = 'com.example.notes:/oauth/identvia';

class MemStore implements SecureStorageAdapter {
  m = new Map<string, string>();
  async getItem(k: string) { return this.m.get(k) ?? null; }
  async setItem(k: string, v: string) { this.m.set(k, v); }
  async deleteItem(k: string) { this.m.delete(k); }
}

/** Like Hermes: no SubtleCrypto. */
const hermesLike: CryptoProvider = {
  getRandomBytes: (n) => new Uint8Array(webcrypto.getRandomValues(new Uint8Array(n))),
  sha256: async (s) => new Uint8Array(createHash('sha256').update(s).digest()),
};

async function setup(o: { crypto?: CryptoProvider; deny?: boolean; stage5?: boolean; tamper?: (u: string) => string; leeway?: number; signature?: 'auto' | 'required' } = {}) {
  const f = await createFake({ redirectUris: [REDIRECT], ...(o.stage5 ? { stage5: true } : {}) });
  const opened: string[] = [];
  const authSession: AuthSessionAdapter = { open: vi.fn(async (url: string, ru: string) => {
    opened.push(url);
    if (url.includes('/oauth/logout')) return { type: 'success' as const, url: ru };
    const cb = f.authorize(url, { deny: !!o.deny });
    return { type: 'success' as const, url: o.tamper ? o.tamper(cb) : cb };
  }) };
  const storage = new MemStore();
  const client = new IdentviaNativeClient({ issuer: ISSUER, clientId: f.clientId, redirectUri: REDIRECT, crypto: o.crypto ?? webCryptoProvider(webcrypto as unknown as Crypto), authSession, storage, fetch: f.fetch as unknown as typeof fetch, ...(o.leeway ? { refreshLeewaySec: o.leeway } : {}), ...(o.signature ? { idTokenSignature: o.signature } : {}) });
  return { f, client, storage, opened, authSession };
}

describe('PKCE and helpers', () => {
  it('RFC 7636 vector with both providers', async () => {
    for (const p of [webCryptoProvider(webcrypto as unknown as Crypto), hermesLike]) expect(await codeChallenge(p, 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk')).toBe('E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM');
  });
  it('URL parser handles custom schemes without the RN URL global', () => {
    const u = parseUrl('com.example.notes:/oauth/identvia?code=a%2Bb&state=x&state=y&iss=https%3A%2F%2Fid.identvia.com');
    expect(u.scheme).toBe('com.example.notes');
    expect(u.path).toBe('/oauth/identvia');
    expect(u.query).toEqual({ code: 'a+b', state: 'x', iss: 'https://id.identvia.com' });
    expect(withQuery('https://a/b?x=1', { y: 'a b', z: undefined })).toBe('https://a/b?x=1&y=a%20b');
  });
  it('redirect URI rules (RFC 8252)', () => {
    expect(assertNativeRedirect('com.example.app:/cb')).toBeTruthy();
    expect(assertNativeRedirect('https://app.example.com/identvia/callback')).toBeTruthy();
    expect(assertNativeRedirect('http://127.0.0.1:8123/cb')).toBeTruthy();
    for (const bad of ['myapp://cb', 'http://app.example.com/cb', 'javascript:alert(1)', 'com.example.app:/cb#x', 'https://u:p@a.example/cb']) expect(() => assertNativeRedirect(bad)).toThrow(ConfigurationError);
  });
  it('refuses a client secret', () => {
    expect(() => new IdentviaNativeClient({ clientId: 'x', redirectUri: REDIRECT, clientSecret: 'nope' } as never)).toThrow(/client secret/);
  });
});

describe('sign-in through the system browser', () => {
  it('signs in, validates, stores tokens securely (refresh token on its own key)', async () => {
    const { client, storage, opened, f } = await setup();
    const s = await client.signIn({ prompt: 'login' });
    expect(s.user.email).toBe('ada@example.com');
    const q = parseUrl(opened[0]!).query;
    expect(q.code_challenge_method).toBe('S256');
    expect(q.redirect_uri).toBe(REDIRECT);
    expect(q.prompt).toBe('login');
    expect([...storage.m.keys()].sort()).toEqual([`identvia.${f.clientId}.rt`, `identvia.${f.clientId}.session`]);
    expect(storage.m.get(`identvia.${f.clientId}.session`)).not.toContain('rt_');
    expect(f.calls.find((c) => c.url.endsWith('/oauth/token'))!.body!.get('client_secret')).toBeNull();
  });
  it('cancel → CancelledError, nothing stored', async () => {
    const { client, authSession, storage } = await setup();
    (authSession.open as ReturnType<typeof vi.fn>).mockResolvedValueOnce({ type: 'cancel' });
    await expect(client.signIn()).rejects.toBeInstanceOf(CancelledError);
    expect(storage.m.size).toBe(0);
  });
  it('denied consent → AuthorizationError(access_denied)', async () => {
    const { client } = await setup({ deny: true });
    await expect(client.signIn()).rejects.toMatchObject({ error: 'access_denied' });
    void AuthorizationError;
  });
  it.each([
    ['forged state', (u: string) => u.replace(/state=[^&]+/, 'state=forged')],
    ['wrong issuer', (u: string) => u.replace(/iss=[^&]+/, 'iss=https%3A%2F%2Fevil.example')],
    ['missing issuer', (u: string) => u.replace(/&?iss=[^&]+/, '')],
    ['another app\'s redirect', (u: string) => u.replace('com.example.notes:', 'com.evil.app:')],
  ])('rejects %s', async (_n, tamper) => {
    const { client } = await setup({ tamper });
    await expect(client.signIn()).rejects.toBeInstanceOf(InvalidStateError);
  });
  it('rejects nonce replay', async () => {
    const { client, f } = await setup();
    f.state.issNonce = 'attacker';
    await expect(client.signIn()).rejects.toThrow(/nonce/);
  });
  it('verifies signatures when SubtleCrypto exists', async () => {
    const { client, f } = await setup();
    const other = await generateKeyPair('RS256');
    f.state.idTokenOverride = (c) => new SignJWT(c).setProtectedHeader({ alg: 'RS256', kid: 'k1' }).sign(other.privateKey);
    await expect(client.signIn()).rejects.toThrow(/signature is invalid/);
  });
  it.each([
    ['alg none', async (c: Record<string, unknown>) => `${Buffer.from('{"alg":"none","kid":"k1"}').toString('base64url')}.${Buffer.from(JSON.stringify(c)).toString('base64url')}.`, /algorithm none/],
    ['wrong audience', async (c: Record<string, unknown>, f: Awaited<ReturnType<typeof createFake>>) => f.signWith({ ...c, aud: 'other' }), /aud/],
    ['expired', async (c: Record<string, unknown>, f: Awaited<ReturnType<typeof createFake>>) => f.signWith({ ...c, exp: 1000, iat: 900 }), /expired/],
    ['wrong issuer', async (c: Record<string, unknown>, f: Awaited<ReturnType<typeof createFake>>) => f.signWith({ ...c, iss: 'https://evil.example' }), /issuer/],
  ])('ID token: rejects %s (even without SubtleCrypto)', async (_n, make, re) => {
    const { client, f } = await setup({ crypto: hermesLike });
    f.state.idTokenOverride = (c) => (make as (c: Record<string, unknown>, f: unknown) => Promise<string>)(c, f);
    await expect(client.signIn()).rejects.toThrow(re as RegExp);
  });
  it('without SubtleCrypto: claims checked, signature skipped; "required" refuses', async () => {
    const a = await setup({ crypto: hermesLike });
    await expect(a.client.signIn()).resolves.toBeTruthy();
    const b = await setup({ crypto: hermesLike, signature: 'required' });
    await expect(b.client.signIn()).rejects.toBeInstanceOf(ValidationError);
  });
});

describe('tokens', () => {
  it('refresh rotation, single-flight', async () => {
    const { client, f, storage } = await setup({ leeway: 10_000 });
    await client.signIn();
    const rt1 = storage.m.get(`identvia.${f.clientId}.rt`);
    const [a, b] = await Promise.all([client.getAccessToken(), client.getAccessToken()]);
    expect(a).toBe(b);
    expect(f.calls.filter((c) => c.body?.get('grant_type') === 'refresh_token').length).toBe(1);
    expect(storage.m.get(`identvia.${f.clientId}.rt`)).not.toBe(rt1);
  });
  it('reuse detection signs out', async () => {
    const { client, f, storage } = await setup({ leeway: 10_000 });
    await client.signIn();
    const old = storage.m.get(`identvia.${f.clientId}.rt`)!;
    await client.getAccessToken();
    await f.fetch(`${ISSUER}/oauth/token`, { method: 'POST', body: `grant_type=refresh_token&refresh_token=${old}&client_id=${f.clientId}` });
    await expect(client.getAccessToken()).rejects.toMatchObject({ error: 'login_required' });
    expect(storage.m.size).toBe(0);
    void TokenError;
  });
  it('session survives an app restart (new client, same storage)', async () => {
    const { client, f, storage, authSession } = await setup();
    await client.signIn();
    const again = new IdentviaNativeClient({ issuer: ISSUER, clientId: f.clientId, redirectUri: REDIRECT, crypto: hermesLike, authSession, storage, fetch: f.fetch as unknown as typeof fetch });
    expect((await again.getSession())?.user.sub).toBe(f.state.userSub);
    expect(await again.getAccessToken()).toBeTruthy();
    expect((await again.userinfo()).sub).toBe(f.state.userSub);
  });
  it('signOut revokes, deletes, and can end the Identvia session in the system browser', async () => {
    const { client, f, storage, opened } = await setup();
    await client.signIn();
    await client.signOut({ federated: true });
    expect(f.revokedFamilies.size).toBe(1);
    expect(storage.m.size).toBe(0);
    const q = parseUrl(opened.at(-1)!).query;
    expect(q.id_token_hint).toBeTruthy();
    expect(q.post_logout_redirect_uri).toBe(REDIRECT);
  });
  it('authorization_details needs server 2026-10-21_5+', async () => {
    const old = await setup();
    await expect(old.client.signIn({ authorizationDetails: [{ type: 'agent_task', description: 'x' }] })).rejects.toBeInstanceOf(UnsupportedError);
    const s5 = await setup({ stage5: true });
    const s = await s5.client.signIn({ authorizationDetails: [{ type: 'agent_task', description: 'Order groceries' }] });
    expect(s.tokens.authorizationDetails?.[0]?.type).toBe('agent_task');
  });
});
