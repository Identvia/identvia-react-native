const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
const URL_ALPHABET = A + '-_';
const STD_ALPHABET = A + '+/';

export function base64UrlEncode(bytes: Uint8Array): string { return encode(bytes, URL_ALPHABET); }

function encode(bytes: Uint8Array, alphabet: string): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i]! << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    out += alphabet[(n >> 18) & 63]! + alphabet[(n >> 12) & 63]!;
    if (i + 1 < bytes.length) out += alphabet[(n >> 6) & 63]!;
    if (i + 2 < bytes.length) out += alphabet[n & 63]!;
  }
  return out;
}

/** Accepts base64url or standard base64 (with or without padding). */
export function base64Decode(s: string): Uint8Array {
  const clean = s.replace(/=+$/, '');
  if (!/^[A-Za-z0-9+/_-]*$/.test(clean)) throw new Error('not base64');
  const out: number[] = [];
  let buf = 0, bits = 0;
  for (const ch of clean) {
    const v = ch === '-' || ch === '+' ? 62 : ch === '_' || ch === '/' ? 63 : A.indexOf(ch);
    buf = (buf << 6) | v; bits += 6;
    if (bits >= 8) { bits -= 8; out.push((buf >> bits) & 0xff); }
  }
  return new Uint8Array(out);
}

export function utf8Encode(s: string): Uint8Array {
  if (typeof TextEncoder !== 'undefined') return new TextEncoder().encode(s);
  const out: number[] = [];
  const str = unescape(encodeURIComponent(s));
  for (let i = 0; i < str.length; i++) out.push(str.charCodeAt(i));
  return new Uint8Array(out);
}

export function utf8Decode(b: Uint8Array): string {
  if (typeof TextDecoder !== 'undefined') return new TextDecoder().decode(b);
  let s = '';
  for (const x of b) s += String.fromCharCode(x);
  return decodeURIComponent(escape(s));
}

export function base64Encode(bytes: Uint8Array): string { const s = encode(bytes, STD_ALPHABET); return s + '='.repeat((4 - (s.length % 4)) % 4); }
