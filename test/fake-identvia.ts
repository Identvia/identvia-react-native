/**
 * In-memory Identvia that behaves like the real server (app/src/Http/Controllers/OAuthController.php):
 * exact redirect match, PKCE S256 required, nonce required for openid, RFC 9207 iss, pairwise sub,
 * single-use codes, refresh rotation with reuse detection (revokes the family), RFC 7009 revoke.
 * Stage-5 endpoints (token exchange, CIBA, authorization_details) can be switched on.
 */
import { SignJWT, exportJWK, generateKeyPair, type KeyLike } from 'jose';
import { createHash, randomBytes } from 'node:crypto';

export const ISSUER = 'https://id.identvia.test';

function b64u(b: Buffer) { return b.toString('base64url'); }
function sha256b64u(s: string) { return b64u(createHash('sha256').update(s).digest()); }

export interface FakeOptions { stage5?: boolean; clientId?: string; redirectUris?: string[]; secret?: string; accessTtl?: number; alg?: 'RS256' }

export async function createFake(opt: FakeOptions = {}) {
  const clientId = opt.clientId ?? 'idv_test_client';
  const redirectUris = opt.redirectUris ?? ['https://app.example.com/callback', 'https://app.example.com/popup.html', 'http://localhost:3000/auth/callback'];
  const { privateKey, publicKey } = await generateKeyPair('RS256', { extractable: true });
  const jwk = { ...(await exportJWK(publicKey)), kid: 'k1', use: 'sig', alg: 'RS256' };
  let signKey: KeyLike = privateKey;
  let kid = 'k1';
  const jwks = { keys: [jwk] as Record<string, unknown>[] };
  const codes = new Map<string, { challenge: string; redirectUri: string; nonce?: string; scope: string; sub: string; used: boolean; details?: unknown }>();
  const refresh = new Map<string, { family: string; used: boolean; sub: string; scope: string }>();
  const revokedFamilies = new Set<string>();
  const access = new Map<string, { sub: string; scope: string; family?: string; exp: number }>();
  const ciba = new Map<string, { status: 'pending' | 'approved' | 'denied'; sub: string; polls: number; slowDownOnce: boolean }>();
  const calls: { url: string; method: string; body?: URLSearchParams; headers: Record<string, string> }[] = [];
  let now = () => Date.now();
  const state = { userSub: 'pw_' + b64u(randomBytes(12)), email: 'ada@example.com', omitIss: false, wrongIss: false, issNonce: undefined as string | undefined, idTokenOverride: undefined as undefined | ((claims: Record<string, unknown>) => Promise<string> | string), rotate: true, jwksFetches: 0 };

  const discovery: Record<string, unknown> = {
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/oauth/authorize`,
    token_endpoint: `${ISSUER}/oauth/token`,
    userinfo_endpoint: `${ISSUER}/oauth/userinfo`,
    jwks_uri: `${ISSUER}/oauth/jwks.json`,
    revocation_endpoint: `${ISSUER}/oauth/revoke`,
    introspection_endpoint: `${ISSUER}/oauth/introspect`,
    end_session_endpoint: `${ISSUER}/oauth/logout`,
    scopes_supported: ['openid', 'email', 'profile', 'offline_access', 'grants:read', 'grants:revoke', 'agent:request'],
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    subject_types_supported: ['pairwise'],
    id_token_signing_alg_values_supported: ['RS256'],
    token_endpoint_auth_methods_supported: ['client_secret_basic', 'client_secret_post', 'none'],
    code_challenge_methods_supported: ['S256'],
    authorization_response_iss_parameter_supported: true,
  };
  if (opt.stage5) {
    (discovery.grant_types_supported as string[]).push('urn:ietf:params:oauth:grant-type:token-exchange', 'urn:openid:params:grant-type:ciba');
    discovery.backchannel_authentication_endpoint = `${ISSUER}/oauth/bc-authorize`;
    discovery.backchannel_token_delivery_modes_supported = ['poll', 'ping'];
    discovery.authorization_details_types_supported = ['agent_task'];
  }

  async function idToken(sub: string, nonce: string | undefined, at: string) {
    const t = Math.floor(now() / 1000);
    const claims: Record<string, unknown> = { iss: ISSUER, sub, aud: clientId, azp: clientId, iat: t, exp: t + 600, auth_time: t, amr: ['pwd'], email: state.email, email_verified: true, name: 'Ada Lovelace', at_hash: b64u(createHash('sha256').update(at).digest().subarray(0, 16)) };
    if (nonce) claims.nonce = nonce;
    if (state.idTokenOverride) return state.idTokenOverride(claims);
    return new SignJWT(claims).setProtectedHeader({ alg: 'RS256', kid, typ: 'JWT' }).sign(signKey);
  }

  function json(status: number, body: unknown, headers: Record<string, string> = {}) {
    const text = body === undefined ? '' : JSON.stringify(body);
    return { ok: status >= 200 && status < 300, status, headers: new Headers({ 'content-type': 'application/json', ...headers }), text: async () => text };
  }

  function clientAuth(body: URLSearchParams, headers: Record<string, string>): boolean {
    const h = headers.authorization ?? headers.Authorization;
    let id = body.get('client_id'), secret = body.get('client_secret');
    if (h?.startsWith('Basic ')) {
      const [a, b] = Buffer.from(h.slice(6), 'base64').toString().split(':');
      id = decodeURIComponent((a ?? '').replace(/\+/g, ' ')); secret = decodeURIComponent((b ?? '').replace(/\+/g, ' '));
    }
    if (id !== clientId) return false;
    if (opt.secret) return secret === opt.secret;
    return true;
  }

  async function issue(sub: string, scope: string, nonce: string | undefined, family?: string, withId = true) {
    const at = 'at_' + b64u(randomBytes(24));
    const ttl = opt.accessTtl ?? 600;
    access.set(at, { sub, scope, exp: now() + ttl * 1000, ...(family ? { family } : {}) });
    const out: Record<string, unknown> = { token_type: 'Bearer', access_token: at, expires_in: ttl, scope };
    if (withId && scope.split(' ').includes('openid')) out.id_token = await idToken(sub, nonce, at);
    if (scope.split(' ').includes('offline_access')) {
      const fam = family ?? b64u(randomBytes(8));
      const rt = 'rt_' + b64u(randomBytes(24));
      refresh.set(rt, { family: fam, used: false, sub, scope });
      out.refresh_token = rt;
      access.get(at)!.family = fam;
    }
    return out;
  }

  const fetch = async (input: string, init: { method?: string; headers?: Record<string, string>; body?: string } = {}) => {
    const u = new URL(input);
    const headers: Record<string, string> = {};
    for (const [k, v] of Object.entries(init.headers ?? {})) headers[k.toLowerCase()] = v;
    const body = init.body ? new URLSearchParams(init.body) : undefined;
    calls.push({ url: input, method: init.method ?? 'GET', ...(body ? { body } : {}), headers });
    if (u.origin !== ISSUER) throw new TypeError('fetch failed: ' + u.origin);
    switch (u.pathname) {
      case '/.well-known/openid-configuration': return json(200, discovery);
      case '/oauth/jwks.json': state.jwksFetches++; return json(200, jwks);
      case '/oauth/token': {
        if (!body || !clientAuth(body, headers)) return json(401, { error: 'invalid_client' });
        const gt = body.get('grant_type');
        if (gt === 'authorization_code') {
          const c = codes.get(body.get('code') ?? '');
          if (!c) return json(400, { error: 'invalid_grant', error_description: 'unknown code' });
          if (c.used) return json(400, { error: 'invalid_grant', error_description: 'code reused' });
          c.used = true;
          if (c.redirectUri !== body.get('redirect_uri')) return json(400, { error: 'invalid_grant', error_description: 'redirect_uri mismatch' });
          if (sha256b64u(body.get('code_verifier') ?? '') !== c.challenge) return json(400, { error: 'invalid_grant', error_description: 'PKCE verification failed' });
          const out = await issue(c.sub, c.scope, c.nonce);
          if (c.details) out.authorization_details = c.details;
          return json(200, out);
        }
        if (gt === 'refresh_token') {
          const rt = body.get('refresh_token') ?? '';
          const r = refresh.get(rt);
          if (!r || revokedFamilies.has(r.family)) return json(400, { error: 'invalid_grant', error_description: 'refresh token revoked' });
          if (r.used) { revokedFamilies.add(r.family); return json(400, { error: 'invalid_grant', error_description: 'refresh token reuse detected; chain revoked' }); }
          if (state.rotate) r.used = true;
          const out = await issue(r.sub, r.scope, undefined, r.family);
          if (!state.rotate) { refresh.delete(out.refresh_token as string); delete out.refresh_token; }
          return json(200, out);
        }
        if (opt.stage5 && gt === 'urn:ietf:params:oauth:grant-type:token-exchange') {
          const a = access.get(body.get('subject_token') ?? '');
          if (!a || body.get('subject_token_type') !== 'urn:ietf:params:oauth:token-type:access_token') return json(400, { error: 'invalid_grant' });
          const want = (body.get('scope') ?? a.scope).split(' ');
          if (!want.every((s) => a.scope.split(' ').includes(s))) return json(400, { error: 'invalid_scope' });
          const at = 'xt_' + b64u(randomBytes(16));
          access.set(at, { sub: a.sub, scope: want.join(' '), exp: now() + 300_000 });
          return json(200, { access_token: at, issued_token_type: 'urn:ietf:params:oauth:token-type:access_token', token_type: 'Bearer', expires_in: 300, scope: want.join(' ') });
        }
        if (opt.stage5 && gt === 'urn:openid:params:grant-type:ciba') {
          const c = ciba.get(body.get('auth_req_id') ?? '');
          if (!c) return json(400, { error: 'invalid_grant' });
          c.polls++;
          if (c.slowDownOnce && c.polls === 1) return json(400, { error: 'slow_down' });
          if (c.status === 'pending') return json(400, { error: 'authorization_pending' });
          if (c.status === 'denied') return json(403, { error: 'access_denied' });
          return json(200, await issue(c.sub, 'openid email', undefined));
        }
        return json(400, { error: 'unsupported_grant_type' });
      }
      case '/oauth/userinfo': {
        const t = (headers.authorization ?? '').replace(/^Bearer /, '') || body?.get('access_token') || '';
        const a = access.get(t);
        if (!a || a.exp < now() || (a.family && revokedFamilies.has(a.family))) return json(401, { error: 'invalid_token' });
        return json(200, { sub: a.sub, email: state.email, email_verified: true });
      }
      case '/oauth/revoke': {
        if (!body || !clientAuth(body, headers)) return json(401, { error: 'invalid_client' });
        const t = body.get('token') ?? '';
        const r = refresh.get(t);
        if (r) revokedFamilies.add(r.family);
        access.delete(t);
        return { ok: true, status: 200, headers: new Headers(), text: async () => '' };
      }
      case '/oauth/introspect': {
        if (!body || !opt.secret || !clientAuth(body, headers)) return json(401, { error: 'invalid_client' });
        const a = access.get(body.get('token') ?? '');
        return json(200, a ? { active: true, sub: a.sub, scope: a.scope, client_id: clientId } : { active: false });
      }
      case '/oauth/bc-authorize': {
        if (!opt.stage5) return json(404, { error: 'not_found' });
        if (!body || !opt.secret || !clientAuth(body, headers)) return json(401, { error: 'invalid_client' });
        if (!body.get('login_hint') && !body.get('id_token_hint')) return json(400, { error: 'invalid_request' });
        const id = 'ar_' + b64u(randomBytes(12));
        ciba.set(id, { status: 'pending', sub: body.get('login_hint') ?? state.userSub, polls: 0, slowDownOnce: false });
        return json(200, { auth_req_id: id, expires_in: 120, interval: 2 });
      }
    }
    return json(404, { error: 'not_found' });
  };

  /** Simulates the user signing in and consenting on Identvia; returns the callback URL Identvia would redirect to. */
  function authorize(authorizeUrl: string, opts: { deny?: boolean; sub?: string } = {}): string {
    const u = new URL(authorizeUrl);
    const p = u.searchParams;
    if (u.origin + u.pathname !== `${ISSUER}/oauth/authorize`) throw new Error('wrong authorize endpoint');
    if (p.get('client_id') !== clientId) throw new Error('Unknown app');
    const ru = p.get('redirect_uri') ?? '';
    if (!redirectUris.includes(ru)) throw new Error('Invalid redirect');
    const back = new URL(ru);
    const st = p.get('state');
    const fail = (e: string) => { back.searchParams.set('error', e); back.searchParams.set('iss', ISSUER); if (st) back.searchParams.set('state', st); return back.toString(); };
    if (!st) return fail('invalid_request');
    if (p.get('response_type') !== 'code') return fail('unsupported_response_type');
    if (p.get('code_challenge_method') !== 'S256' || !/^[A-Za-z0-9\-._~]{43,128}$/.test(p.get('code_challenge') ?? '')) return fail('invalid_request');
    const scope = p.get('scope') ?? 'openid';
    if (scope.split(' ').includes('openid') && !p.get('nonce')) return fail('invalid_request');
    let details: unknown;
    if (p.has('authorization_details')) {
      if (!opt.stage5) return fail('invalid_request');
      details = JSON.parse(p.get('authorization_details')!);
      if (!Array.isArray(details) || !details.every((d: { type?: string }) => d.type === 'agent_task')) return fail('invalid_authorization_details');
    }
    if (opts.deny) return fail('access_denied');
    const code = 'c_' + b64u(randomBytes(24));
    codes.set(code, { challenge: p.get('code_challenge')!, redirectUri: ru, nonce: state.issNonce ?? p.get('nonce') ?? undefined, scope, sub: opts.sub ?? state.userSub, used: false, details });
    back.searchParams.set('code', code);
    back.searchParams.set('state', st);
    if (state.wrongIss) back.searchParams.set('iss', 'https://evil.example');
    else if (!state.omitIss) back.searchParams.set('iss', ISSUER);
    return back.toString();
  }

  async function rotateKey() {
    const kp = await generateKeyPair('RS256', { extractable: true });
    kid = 'k' + (jwks.keys.length + 1);
    signKey = kp.privateKey;
    jwks.keys.push({ ...(await exportJWK(kp.publicKey)), kid, use: 'sig', alg: 'RS256' });
  }

  return {
    fetch, authorize, rotateKey, state, calls, clientId, refresh, revokedFamilies, ciba, discovery,
    setNow(f: () => number) { now = f; },
    signWith: (claims: Record<string, unknown>, header: Record<string, unknown> = { alg: 'RS256', kid: 'k1' }) => new SignJWT(claims).setProtectedHeader(header as { alg: string }).sign(signKey),
  };
}
