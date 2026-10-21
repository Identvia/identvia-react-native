import { AndroidConfig, createRunOncePlugin, withAndroidManifest, withEntitlementsPlist, withInfoPlist, type ConfigPlugin } from '@expo/config-plugins';

export interface IdentviaPluginProps {
  /**
   * The redirect URI registered for your app, e.g. "com.example.app:/oauth/identvia" (private-use scheme) or
   * "https://app.example.com/identvia/callback" (Universal Link / App Link; needs your apple-app-site-association / assetlinks.json).
   */
  redirectUri: string;
}

function parse(uri: string): { scheme: string; host?: string; path: string } {
  const m = /^([a-z][a-z0-9+.\-]*):(?:\/\/([^/?#]*))?([^?#]*)/i.exec(uri);
  if (!m) throw new Error(`[@identvia/react-native] redirectUri "${uri}" is not a valid URI`);
  const scheme = m[1]!.toLowerCase();
  if (scheme !== 'https' && !/^[a-z][a-z0-9+\-]*(\.[a-z0-9+\-]+)+$/.test(scheme)) {
    throw new Error(`[@identvia/react-native] Use https or a reverse-domain scheme like com.example.app (RFC 8252), not "${scheme}"`);
  }
  return { scheme, ...(m[2] ? { host: m[2] } : {}), path: m[3] || '/' };
}

const withIdentviaIos: ConfigPlugin<IdentviaPluginProps> = (config, { redirectUri }) => {
  const r = parse(redirectUri);
  if (r.scheme === 'https') {
    return withEntitlementsPlist(config, (c) => {
      const key = 'com.apple.developer.associated-domains';
      const list = new Set<string>((c.modResults[key] as string[] | undefined) ?? []);
      list.add(`applinks:${r.host}`);
      c.modResults[key] = [...list];
      return c;
    });
  }
  return withInfoPlist(config, (c) => {
    const types = (c.modResults.CFBundleURLTypes ?? []) as { CFBundleURLSchemes: string[] }[];
    if (!types.some((t) => t.CFBundleURLSchemes?.includes(r.scheme))) types.push({ CFBundleURLSchemes: [r.scheme] });
    c.modResults.CFBundleURLTypes = types;
    return c;
  });
};

const withIdentviaAndroid: ConfigPlugin<IdentviaPluginProps> = (config, { redirectUri }) => {
  const r = parse(redirectUri);
  return withAndroidManifest(config, (c) => {
    const activity = AndroidConfig.Manifest.getMainActivityOrThrow(c.modResults);
    const filters = (activity['intent-filter'] ??= []);
    const data: Record<string, string> = { 'android:scheme': r.scheme };
    if (r.host) data['android:host'] = r.host;
    if (r.scheme === 'https') data['android:path'] = r.path;
    const exists = filters.some((f) => (f.data ?? []).some((d) => d.$['android:scheme'] === r.scheme && (d.$ as Record<string, string>)['android:host'] === r.host));
    if (!exists) {
      filters.push({
        $: r.scheme === 'https' ? ({ 'android:autoVerify': 'true' } as never) : ({} as never),
        action: [{ $: { 'android:name': 'android.intent.action.VIEW' } }],
        category: [{ $: { 'android:name': 'android.intent.category.DEFAULT' } }, { $: { 'android:name': 'android.intent.category.BROWSABLE' } }],
        data: [{ $: data as never }],
      });
    }
    return c;
  });
};

const withIdentvia: ConfigPlugin<IdentviaPluginProps> = (config, props) => {
  if (!props?.redirectUri) throw new Error('[@identvia/react-native] plugin option "redirectUri" is required');
  return withIdentviaAndroid(withIdentviaIos(config, props), props);
};

export default createRunOncePlugin(withIdentvia, '@identvia/react-native', '0.1.0');
export { parse as parseRedirectUri };
