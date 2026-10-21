import { base64Decode, base64UrlEncode, utf8Decode, utf8Encode } from './encoding';
import { timingSafeEqual, type CryptoProvider } from './crypto';
import { ValidationError } from './errors';

export const ALLOWED_ALGS = ['RS256', 'ES256'] as const;

export interface IdTokenClaims {
  iss: string; sub: string; aud: string | string[]; exp: number; iat: number;
  auth_time?: number; nonce?: string; azp?: string; amr?: string[]; at_hash?: string;
  email?: string; email_verified?: boolean; name?: string; given_name?: string; family_name?: string; picture?: string;
  [k: string]: unknown;
}

export interface Jwk { kty: string; kid?: string; use?: string; alg?: string; n?: string; e?: string; crv?: string; x?: string; y?: string }

export function decodeJwt(jwt: string): { header: { alg?: string; kid?: string; typ?: string }; claims: IdTokenClaims; signingInput: string; signature: Uint8Array } {
  const parts = typeof jwt === 'string' ? jwt.split('.') : [];
  if (parts.length !== 3 || !parts[0] || !parts[1]) throw new ValidationError('ID token is not a signed JWT.');
  try {
    return {
      header: JSON.parse(utf8Decode(base64Decode(parts[0]))),
      claims: JSON.parse(utf8Decode(base64Decode(parts[1]))),
      signingInput: `${parts[0]}.${parts[1]}`,
      signature: base64Decode(parts[2] ?? ''),
    };
  } catch { throw new ValidationError('ID token is malformed.'); }
}

/** Verifies an RS256/ES256 JWS with Web Crypto. */
export async function verifySignature(subtle: SubtleCrypto, alg: string, jwk: Jwk, signingInput: string, signature: Uint8Array): Promise<boolean> {
  const data = utf8Encode(signingInput) as Uint8Array<ArrayBuffer>;
  const sig = signature as Uint8Array<ArrayBuffer>;
  if (alg === 'RS256') {
    if (jwk.kty !== 'RSA') return false;
    const key = await subtle.importKey('jwk', { kty: 'RSA', n: jwk.n, e: jwk.e, ext: true } as JsonWebKey, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
    return subtle.verify('RSASSA-PKCS1-v1_5', key, sig, data);
  }
  if (alg === 'ES256') {
    if (jwk.kty !== 'EC' || jwk.crv !== 'P-256' || sig.length !== 64) return false;
    const key = await subtle.importKey('jwk', { kty: 'EC', crv: 'P-256', x: jwk.x, y: jwk.y, ext: true } as JsonWebKey, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
    return subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, sig, data);
  }
  return false;
}

export interface ValidateOptions {
  issuer: string; clientId: string; nonce?: string; requireNonce?: boolean; maxAge?: number; accessToken?: string;
  nowSec: number; toleranceSec?: number; crypto: CryptoProvider;
  /** Resolves the signing key by kid (refetching JWKS once on a miss). */
  getKey: (kid: string) => Promise<Jwk | undefined>;
  /**
   * 'auto' (default): verify the signature when Web Crypto is available; otherwise rely on the direct TLS channel to the
   * token endpoint, which OIDC Core §3.1.3.7 step 6 allows for the code flow. 'required' fails without Web Crypto.
   */
  signature?: 'auto' | 'required';
}

export async function validateIdToken(jwt: string, o: ValidateOptions): Promise<IdTokenClaims & { signatureVerified: boolean }> {
  const { header, claims: c, signingInput, signature } = decodeJwt(jwt);
  const tol = o.toleranceSec ?? 60;
  if (!header.alg || !(ALLOWED_ALGS as readonly string[]).includes(header.alg)) throw new ValidationError(`ID token algorithm ${String(header.alg)} is not allowed.`);
  if (!header.kid) throw new ValidationError('ID token has no key ID (kid).');
  let verified = false;
  if (o.crypto.subtle) {
    const jwk = await o.getKey(header.kid);
    if (!jwk) throw new ValidationError('ID token was signed with an unknown key.');
    if (jwk.alg && jwk.alg !== header.alg) throw new ValidationError('ID token algorithm does not match its key.');
    if (!(await verifySignature(o.crypto.subtle, header.alg, jwk, signingInput, signature))) throw new ValidationError('ID token signature is invalid.');
    verified = true;
  } else if (o.signature === 'required') {
    throw new ValidationError('Signature verification is required but no SubtleCrypto is available (install react-native-quick-crypto).');
  }
  if (c.iss !== o.issuer) throw new ValidationError('ID token issuer mismatch.');
  const auds = Array.isArray(c.aud) ? c.aud : [c.aud];
  if (!auds.includes(o.clientId)) throw new ValidationError('ID token was not issued for this app (aud).');
  if (auds.length > 1 && c.azp !== o.clientId) throw new ValidationError('ID token azp mismatch.');
  if (c.azp !== undefined && c.azp !== o.clientId) throw new ValidationError('ID token azp mismatch.');
  if (typeof c.sub !== 'string' || c.sub === '' || c.sub.length > 255) throw new ValidationError('ID token has no subject.');
  if (typeof c.exp !== 'number' || typeof c.iat !== 'number') throw new ValidationError('ID token is missing exp/iat.');
  if (c.exp + tol < o.nowSec) throw new ValidationError('ID token has expired.');
  if (c.iat > o.nowSec + tol) throw new ValidationError('ID token was issued in the future.');
  if (o.nonce !== undefined || o.requireNonce) {
    if (typeof c.nonce !== 'string' || o.nonce === undefined || !timingSafeEqual(c.nonce, o.nonce)) throw new ValidationError('ID token nonce mismatch (possible replay).');
  }
  if (o.maxAge !== undefined) {
    if (typeof c.auth_time !== 'number') throw new ValidationError('ID token has no auth_time but max_age was requested.');
    if (c.auth_time + o.maxAge + tol < o.nowSec) throw new ValidationError('The user signed in too long ago for the requested max_age.');
  }
  if (c.at_hash !== undefined && o.accessToken) {
    const h = base64UrlEncode((await o.crypto.sha256(o.accessToken)).slice(0, 16));
    if (!timingSafeEqual(h, String(c.at_hash))) throw new ValidationError('ID token at_hash does not match the access token.');
  }
  return { ...c, signatureVerified: verified };
}
