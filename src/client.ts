import { codeChallenge, randomToken, timingSafeEqual, type CryptoProvider } from './crypto';
import { AuthorizationError, CancelledError, ConfigurationError, IdentviaError, InvalidStateError, TokenError, UnsupportedError, ValidationError } from './errors';
import { validateIdToken, type IdTokenClaims, type Jwk } from './idtoken';
import { parseUrl, withQuery } from './url';

export const DEFAULT_ISSUER = 'https://id.identvia.com';

/** Opens the system browser auth session (ASWebAuthenticationSession on iOS, Custom Tabs on Android). Never a WebView. */
export interface AuthSessionAdapter {
  open(authorizeUrl: string, redirectUri: string, opts: { ephemeral: boolean }): Promise<{ type: 'success'; url: string } | { type: 'cancel' | 'dismiss' | 'locked' }>;
}

/** Secure key-value storage (Keychain / Android Keystore-backed). */
export interface SecureStorageAdapter {
  getItem(key: string): Promise<string | null>;
  setItem(key: string, value: string): Promise<void>;
  deleteItem(key: string): Promise<void>;
}

export interface AuthorizationDetail { type: string; [k: string]: unknown }

export interface IdentviaNativeConfig {
  issuer?: string;
  clientId: string;
  /**
   * Your registered redirect URI. Prefer an https App Link / Universal Link you own (https://app.example.com/identvia/callback).
   * Private-use schemes in reverse-domain form (com.example.app:/oauth/callback) need a "native" client on the server.
   */
  redirectUri: string;
  scopes?: string[];
  crypto: CryptoProvider;
  authSession: AuthSessionAdapter;
  storage: SecureStorageAdapter;
  fetch?: typeof fetch;
  /** iOS: don't share cookies with Safari (no "Sign in with Identvia wants to use…" prompt, but no SSO). Default false. */
  ephemeralSession?: boolean;
  refreshLeewaySec?: number;
  idTokenSignature?: 'auto' | 'required';
  now?: () => number;
}

export interface Tokens { accessToken: string; expiresAt: number; refreshToken?: string; idToken?: string; scope?: string; authorizationDetails?: AuthorizationDetail[] }
export interface NativeSession { user: IdTokenClaims; tokens: Tokens }
export interface SignInOptions { scopes?: string[]; prompt?: 'none' | 'login' | 'consent'; maxAge?: number; loginHint?: string; uiLocales?: string[]; authorizationDetails?: AuthorizationDetail[] }

const LOOPBACK = ['localhost', '127.0.0.1', '[::1]'];

export function assertNativeRedirect(uri: string): string {
  let u;
  try { u = parseUrl(uri); } catch { throw new ConfigurationError(`redirectUri "${uri}" is not an absolute URI.`); }
  if (u.hasFragment) throw new ConfigurationError('redirectUri must not contain a #fragment.');
  if (u.userinfo) throw new ConfigurationError('redirectUri must not contain credentials.');
  if (u.scheme === 'https' && u.hostname) return uri;
  if (u.scheme === 'http' && LOOPBACK.includes(u.hostname)) return uri;
  const scheme = u.scheme;
  if (/^[a-z][a-z0-9+\-]*(\.[a-z0-9+\-]+)+$/.test(scheme)) return uri; // RFC 8252 §7.1 reverse-domain private-use scheme
  throw new ConfigurationError('redirectUri must be https://, http://localhost, or a reverse-domain scheme like com.example.app:/callback (never "myapp://").');
}

/** The returned URL must be our redirect URI (same scheme, host and path). */
export function isSameRedirect(registered: string, got: string): boolean {
  try {
    const a = parseUrl(registered), b = parseUrl(got);
    return a.scheme === b.scheme && a.host === b.host && (a.path || '/') === (b.path || '/');
  } catch { return false; }
}

export class IdentviaNativeClient {
  readonly issuer: string;
  readonly clientId: string;
  readonly redirectUri: string;
  readonly scopes: string[];
  private readonly c: IdentviaNativeConfig;
  private readonly fetchFn: typeof fetch;
  private readonly now: () => number;
  private discovery?: Record<string, unknown>;
  private jwks?: { keys: Jwk[]; at: number };
  private session: NativeSession | null | undefined;
  private refreshing?: Promise<NativeSession | null>;
  private listeners = new Set<(s: NativeSession | null) => void>();
  private signingIn = false;

  constructor(c: IdentviaNativeConfig) {
    if ((c as { clientSecret?: unknown }).clientSecret !== undefined) throw new ConfigurationError('Never ship a client secret in a mobile app: it can be extracted. Use a public client (PKCE).');
    if (!c.clientId) throw new ConfigurationError('clientId is required.');
    const iss = (c.issuer ?? DEFAULT_ISSUER).replace(/\/+$/, '');
    const iu = parseUrl(iss);
    if (iu.scheme !== 'https' && !(iu.scheme === 'http' && LOOPBACK.includes(iu.hostname))) throw new ConfigurationError('issuer must use https://.');
    this.issuer = iss;
    this.clientId = c.clientId;
    this.redirectUri = assertNativeRedirect(c.redirectUri);
    this.scopes = [...new Set(['openid', ...(c.scopes ?? ['email', 'profile', 'offline_access'])])];
    this.c = c;
    this.fetchFn = c.fetch ?? fetch;
    this.now = c.now ?? Date.now;
  }

  // -------------------------------------------------------------- events
  onChange(fn: (s: NativeSession | null) => void): () => void { this.listeners.add(fn); return () => { this.listeners.delete(fn); }; }
  private emit(s: NativeSession | null) { for (const l of this.listeners) { try { l(s); } catch { /* */ } } }

  // -------------------------------------------------------------- http
  private async json(url: string, init?: RequestInit): Promise<{ status: number; data: Record<string, unknown> }> {
    let res: Response;
    try { res = await this.fetchFn(url, init); } catch { throw new IdentviaError('network_error', 'Could not reach Identvia. Check your connection.'); }
    const text = await res.text();
    let data: unknown = {};
    if (text) { try { data = JSON.parse(text); } catch { throw new IdentviaError('http_error', `Unexpected response (HTTP ${res.status}).`); } }
    return { status: res.status, data: (data && typeof data === 'object' ? data : {}) as Record<string, unknown> };
  }

  async getDiscovery(): Promise<Record<string, unknown>> {
    if (this.discovery) return this.discovery;
    const { status, data } = await this.json(`${this.issuer}/.well-known/openid-configuration`);
    if (status !== 200) throw new IdentviaError('http_error', `Discovery failed (HTTP ${status}).`);
    if (data.issuer !== this.issuer) throw new ConfigurationError('Discovery issuer does not match the configured issuer.');
    for (const k of ['authorization_endpoint', 'token_endpoint', 'jwks_uri']) if (typeof data[k] !== 'string') throw new ConfigurationError(`Discovery has no ${k}.`);
    const m = data.code_challenge_methods_supported;
    if (Array.isArray(m) && !m.includes('S256')) throw new ConfigurationError('Server does not support PKCE S256.');
    this.discovery = data;
    return data;
  }

  private async endpoint(name: string): Promise<string> {
    const v = (await this.getDiscovery())[name];
    if (typeof v !== 'string') throw new UnsupportedError(`${name} is not available on this server.`);
    return v;
  }

  private async getKey(kid: string): Promise<Jwk | undefined> {
    const load = async () => {
      const { status, data } = await this.json(await this.endpoint('jwks_uri'));
      if (status !== 200 || !Array.isArray(data.keys)) throw new IdentviaError('http_error', 'JWKS fetch failed.');
      this.jwks = { keys: (data.keys as Jwk[]).filter((k) => !k.use || k.use === 'sig'), at: this.now() };
    };
    if (!this.jwks) await load();
    let k = this.jwks!.keys.find((x) => x.kid === kid);
    if (!k && this.now() - this.jwks!.at > 30_000) { await load(); k = this.jwks!.keys.find((x) => x.kid === kid); }
    return k;
  }

  private async post(url: string, form: Record<string, string | undefined>): Promise<Record<string, unknown>> {
    const body = Object.entries({ ...form, client_id: this.clientId }).filter(([, v]) => v !== undefined).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v!)}`).join('&');
    const { status, data } = await this.json(url, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', Accept: 'application/json' }, body });
    if (status < 200 || status >= 300) throw new TokenError(typeof data.error === 'string' ? data.error : 'http_error', typeof data.error_description === 'string' ? data.error_description : undefined, status);
    return data;
  }

  private parseTokens(d: Record<string, unknown>): Tokens {
    if (typeof d.access_token !== 'string' || String(d.token_type).toLowerCase() !== 'bearer') throw new TokenError('invalid_response', 'No Bearer access token in the response.', 200);
    const t: Tokens = { accessToken: d.access_token, expiresAt: this.now() + (typeof d.expires_in === 'number' ? d.expires_in : 600) * 1000 };
    if (typeof d.refresh_token === 'string') t.refreshToken = d.refresh_token;
    if (typeof d.id_token === 'string') t.idToken = d.id_token;
    if (typeof d.scope === 'string') t.scope = d.scope;
    if (Array.isArray(d.authorization_details)) t.authorizationDetails = d.authorization_details as AuthorizationDetail[];
    return t;
  }

  private validate(jwt: string, o: { nonce?: string; requireNonce?: boolean; maxAge?: number; accessToken?: string }) {
    return validateIdToken(jwt, { issuer: this.issuer, clientId: this.clientId, nowSec: Math.floor(this.now() / 1000), crypto: this.c.crypto, getKey: (k) => this.getKey(k), signature: this.c.idTokenSignature ?? 'auto', ...o });
  }

  // -------------------------------------------------------------- sign-in
  /** Builds the request. Exposed for custom adapters and tests. */
  async createAuthorizationRequest(o: SignInOptions = {}) {
    const doc = await this.getDiscovery();
    const state = randomToken(this.c.crypto, 32);
    const nonce = randomToken(this.c.crypto, 32);
    const verifier = randomToken(this.c.crypto, 48);
    const scopes = o.scopes ? [...new Set(['openid', ...o.scopes])] : this.scopes;
    const p: Record<string, string | undefined> = {
      response_type: 'code', client_id: this.clientId, redirect_uri: this.redirectUri, scope: scopes.join(' '), state, nonce,
      code_challenge: await codeChallenge(this.c.crypto, verifier), code_challenge_method: 'S256',
      prompt: o.prompt, max_age: o.maxAge !== undefined ? String(Math.max(0, Math.floor(o.maxAge))) : undefined,
      login_hint: o.loginHint, ui_locales: o.uiLocales?.join(' '),
    };
    if (o.authorizationDetails) {
      const types = doc.authorization_details_types_supported;
      if (!Array.isArray(types)) throw new UnsupportedError('This Identvia server does not support authorization_details (requires server 2026-10-21_5+).');
      for (const d of o.authorizationDetails) if (!types.includes(d.type)) throw new ConfigurationError(`authorization_details type "${d.type}" is not accepted by this server.`);
      p.authorization_details = JSON.stringify(o.authorizationDetails);
    }
    return { url: withQuery(doc.authorization_endpoint as string, p), tx: { state, nonce, verifier, maxAge: o.maxAge !== undefined ? Math.max(0, Math.floor(o.maxAge)) : undefined } };
  }

  /** Completes sign-in from the URL the system browser returned to. */
  async completeAuthorization(returnedUrl: string, tx: { state: string; nonce: string; verifier: string; maxAge?: number }): Promise<NativeSession> {
    let q: Record<string, string>;
    try { q = parseUrl(returnedUrl).query; } catch { throw new InvalidStateError('Sign-in returned an invalid URL.'); }
    if (!isSameRedirect(this.redirectUri, returnedUrl)) throw new InvalidStateError('Sign-in returned to an unexpected address.');
    const state = q.state;
    if (!state || !timingSafeEqual(state, tx.state)) throw new InvalidStateError('Sign-in response does not match this sign-in (state). Try again.');
    const iss = q.iss;
    if (iss !== undefined) { if (iss !== this.issuer) throw new InvalidStateError('Sign-in response came from a different issuer.'); }
    else if ((await this.getDiscovery()).authorization_response_iss_parameter_supported) throw new InvalidStateError('Sign-in response is missing iss.');
    const err = q.error;
    if (err) throw new AuthorizationError(err.slice(0, 100), q.error_description?.slice(0, 500));
    const code = q.code;
    if (!code) throw new InvalidStateError('Sign-in response has no code.');
    const tokens = this.parseTokens(await this.post(await this.endpoint('token_endpoint'), { grant_type: 'authorization_code', code, redirect_uri: this.redirectUri, code_verifier: tx.verifier }));
    if (!tokens.idToken) throw new ValidationError('No ID token returned.');
    const { signatureVerified: _s, ...user } = await this.validate(tokens.idToken, { nonce: tx.nonce, requireNonce: true, maxAge: tx.maxAge, accessToken: tokens.accessToken });
    return { user: user as IdTokenClaims, tokens };
  }

  /** Opens the system browser, completes the flow and stores the session securely. */
  async signIn(o: SignInOptions = {}): Promise<NativeSession> {
    if (this.signingIn) throw new IdentviaError('in_progress', 'A sign-in is already in progress.');
    this.signingIn = true;
    try {
      const { url, tx } = await this.createAuthorizationRequest(o);
      const r = await this.c.authSession.open(url, this.redirectUri, { ephemeral: !!this.c.ephemeralSession });
      if (r.type !== 'success') throw new CancelledError();
      const s = await this.completeAuthorization(r.url, tx);
      await this.save(s);
      return s;
    } finally { this.signingIn = false; }
  }

  // -------------------------------------------------------------- session
  private k(name: string) { return `identvia.${this.clientId.replace(/[^A-Za-z0-9._-]/g, '_')}.${name}`; }

  async getSession(): Promise<NativeSession | null> {
    if (this.session !== undefined) return this.session;
    const [meta, rt] = await Promise.all([this.c.storage.getItem(this.k('session')), this.c.storage.getItem(this.k('rt'))]);
    let s: NativeSession | null = null;
    if (meta) { try { s = JSON.parse(meta) as NativeSession; if (rt) s.tokens.refreshToken = rt; } catch { s = null; } }
    this.session = s;
    return s;
  }

  private async save(s: NativeSession | null) {
    this.session = s;
    if (!s) {
      await Promise.all([this.c.storage.deleteItem(this.k('session')), this.c.storage.deleteItem(this.k('rt'))]);
    } else {
      const { refreshToken, ...rest } = s.tokens;
      // Refresh token on its own key (keeps each Keychain item small; it is the most sensitive value)
      await this.c.storage.setItem(this.k('session'), JSON.stringify({ user: s.user, tokens: rest }));
      if (refreshToken) await this.c.storage.setItem(this.k('rt'), refreshToken); else await this.c.storage.deleteItem(this.k('rt'));
    }
    this.emit(s);
  }

  /** A valid access token; refreshes (rotating the refresh token) when close to expiry. Throws TokenError('login_required'). */
  async getAccessToken(force = false): Promise<string> {
    let s = await this.getSession();
    if (!s) throw new TokenError('login_required', 'Not signed in.', 401);
    if (!force && s.tokens.expiresAt - (this.c.refreshLeewaySec ?? 60) * 1000 > this.now()) return s.tokens.accessToken;
    if (!this.refreshing) this.refreshing = this.doRefresh(s).finally(() => { this.refreshing = undefined; });
    s = await this.refreshing;
    if (!s) throw new TokenError('login_required', 'Your session ended. Please sign in again.', 401);
    return s.tokens.accessToken;
  }

  private async doRefresh(s: NativeSession): Promise<NativeSession | null> {
    if (!s.tokens.refreshToken) { await this.save(null); return null; }
    try {
      const t = this.parseTokens(await this.post(await this.endpoint('token_endpoint'), { grant_type: 'refresh_token', refresh_token: s.tokens.refreshToken }));
      let user = s.user;
      if (t.idToken) {
        const { signatureVerified: _v, ...c } = await this.validate(t.idToken, { accessToken: t.accessToken });
        if (c.sub !== s.user.sub) throw new ValidationError('Refreshed ID token is for a different user.');
        user = c as IdTokenClaims;
      } else t.idToken = s.tokens.idToken;
      if (!t.refreshToken) t.refreshToken = s.tokens.refreshToken;
      const next = { user, tokens: t };
      await this.save(next);
      return next;
    } catch (e) {
      if (e instanceof TokenError && (e.error === 'invalid_grant' || e.status === 401)) { await this.save(null); return null; }
      throw e;
    }
  }

  async userinfo(): Promise<Record<string, unknown> & { sub: string }> {
    const s = await this.getSession();
    const at = await this.getAccessToken();
    const { status, data } = await this.json(await this.endpoint('userinfo_endpoint'), { headers: { Authorization: `Bearer ${at}`, Accept: 'application/json' } });
    if (status === 401) throw new TokenError('invalid_token', 'Access token rejected.', 401);
    if (status !== 200 || typeof data.sub !== 'string') throw new IdentviaError('http_error', `Userinfo failed (HTTP ${status}).`);
    if (s && !timingSafeEqual(s.user.sub, data.sub)) throw new ValidationError('Userinfo is for a different user.');
    return data as Record<string, unknown> & { sub: string };
  }

  /** Revokes the refresh token and deletes the stored session. `federated` also ends the Identvia browser session. */
  async signOut(o: { federated?: boolean; postLogoutRedirectUri?: string } = {}): Promise<void> {
    const s = await this.getSession();
    await this.save(null);
    if (s) {
      const token = s.tokens.refreshToken ?? s.tokens.accessToken;
      try { await this.post(await this.endpoint('revocation_endpoint'), { token, token_type_hint: s.tokens.refreshToken ? 'refresh_token' : 'access_token' }); } catch { /* local sign-out still happened */ }
    }
    if (o.federated) {
      const back = assertNativeRedirect(o.postLogoutRedirectUri ?? this.redirectUri);
      const url = withQuery(await this.endpoint('end_session_endpoint'), { client_id: this.clientId, id_token_hint: s?.tokens.idToken, post_logout_redirect_uri: back });
      await this.c.authSession.open(url, back, { ephemeral: !!this.c.ephemeralSession }).catch(() => undefined);
    }
  }
}
