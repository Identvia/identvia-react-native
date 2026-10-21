/**
 * Minimal URL helpers. React Native's global URL is incomplete (URLSearchParams.get/set throw on older versions),
 * so the SDK never depends on it.
 */
export interface ParsedUrl { scheme: string; host: string; hostname: string; userinfo: string; path: string; query: Record<string, string>; rawQuery: string; hasFragment: boolean }

export function parseUrl(s: string): ParsedUrl {
  const m = /^([a-zA-Z][a-zA-Z0-9+.\-]*):(\/\/([^/?#]*))?([^?#]*)(\?([^#]*))?(#.*)?$/.exec(s);
  if (!m) throw new TypeError('Invalid URL');
  const authority = m[3] ?? '';
  const at = authority.lastIndexOf('@');
  const userinfo = at >= 0 ? authority.slice(0, at) : '';
  const host = (at >= 0 ? authority.slice(at + 1) : authority).toLowerCase();
  const hostname = host.startsWith('[') ? host.slice(0, host.indexOf(']') + 1) : host.split(':')[0]!;
  return { scheme: m[1]!.toLowerCase(), host, hostname, userinfo, path: m[4] ?? '', query: parseQuery(m[6] ?? ''), rawQuery: m[6] ?? '', hasFragment: m[7] !== undefined };
}

export function parseQuery(q: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const part of q.split('&')) {
    if (!part) continue;
    const i = part.indexOf('=');
    const k = dec(i < 0 ? part : part.slice(0, i));
    const v = dec(i < 0 ? '' : part.slice(i + 1));
    if (!(k in out)) out[k] = v; // first wins; duplicates are ignored
  }
  return out;
}

function dec(s: string): string { try { return decodeURIComponent(s.replace(/\+/g, ' ')); } catch { return s; } }

export function withQuery(base: string, params: Record<string, string | undefined>): string {
  const q = Object.entries(params).filter(([, v]) => v !== undefined).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v!)}`).join('&');
  if (!q) return base;
  return base + (base.includes('?') ? '&' : '?') + q;
}
