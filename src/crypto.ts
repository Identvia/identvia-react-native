import { base64UrlEncode, utf8Encode } from './encoding';
import { ConfigurationError } from './errors';

/** Pluggable so the core runs on Hermes (no Web Crypto), Node and the web. */
export interface CryptoProvider {
  getRandomBytes(n: number): Uint8Array;
  sha256(input: string): Promise<Uint8Array>;
  /** Optional Web Crypto SubtleCrypto (e.g. from react-native-quick-crypto) to verify ID token signatures. */
  subtle?: SubtleCrypto;
}

export function webCryptoProvider(c: Crypto | undefined = (globalThis as { crypto?: Crypto }).crypto): CryptoProvider {
  if (!c?.getRandomValues || !c.subtle) throw new ConfigurationError('Web Crypto is not available here; pass a CryptoProvider (the Expo adapter uses expo-crypto).');
  return {
    getRandomBytes: (n) => c.getRandomValues(new Uint8Array(n)),
    sha256: async (s) => new Uint8Array(await c.subtle.digest('SHA-256', utf8Encode(s) as Uint8Array<ArrayBuffer>)),
    subtle: c.subtle,
  };
}

export function randomToken(p: CryptoProvider, bytes = 32): string {
  const b = p.getRandomBytes(bytes);
  if (!(b instanceof Uint8Array) || b.length !== bytes) throw new ConfigurationError('CryptoProvider.getRandomBytes returned the wrong length.');
  return base64UrlEncode(b);
}

/** RFC 7636 §4.2 S256 */
export async function codeChallenge(p: CryptoProvider, verifier: string): Promise<string> {
  if (!/^[A-Za-z0-9\-._~]{43,128}$/.test(verifier)) throw new ConfigurationError('PKCE code_verifier must be 43–128 unreserved characters.');
  return base64UrlEncode(await p.sha256(verifier));
}

export function timingSafeEqual(a: string, b: string): boolean {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  let d = a.length ^ b.length;
  for (let i = 0; i < Math.max(a.length, b.length); i++) d |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
  return d === 0;
}
