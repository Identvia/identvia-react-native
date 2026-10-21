import { describe, expect, it } from 'vitest';
// eslint-disable-next-line @typescript-eslint/no-require-imports
const plugin = require('../plugin/build').default;
const { parseRedirectUri } = require('../plugin/build');

function run(redirectUri: string) {
  const cfg = plugin({ name: 'Notes', slug: 'notes' }, { redirectUri });
  const ios = cfg.mods.ios;
  const android = cfg.mods.android;
  return { cfg, ios, android };
}

describe('Expo config plugin', () => {
  it('parses and rejects unsafe schemes', () => {
    expect(parseRedirectUri('com.example.app:/oauth')).toEqual({ scheme: 'com.example.app', path: '/oauth' });
    expect(() => parseRedirectUri('myapp://cb')).toThrow(/reverse-domain/);
  });
  it('registers a private-use scheme (iOS CFBundleURLTypes, Android intent filter)', async () => {
    const { ios, android } = run('com.example.notes:/oauth/identvia');
    const plist = await ios.infoPlist({ modResults: {}, modRequest: { platform: 'ios' } } as never);
    expect(plist.modResults.CFBundleURLTypes).toEqual([{ CFBundleURLSchemes: ['com.example.notes'] }]);
    const manifest = { manifest: { application: [{ $: { 'android:name': '.MainApplication' }, activity: [{ $: { 'android:name': '.MainActivity' }, 'intent-filter': [] }] }] } };
    const out = await android.manifest({ modResults: manifest, modRequest: { platform: 'android' } } as never);
    const f = out.modResults.manifest.application[0].activity[0]['intent-filter'][0];
    expect(f.data[0].$['android:scheme']).toBe('com.example.notes');
    expect(f.category.map((c: { $: Record<string, string> }) => c.$['android:name'])).toContain('android.intent.category.BROWSABLE');
  });
  it('https redirect → associated domains + verified App Link', async () => {
    const { ios, android } = run('https://notes.example.com/identvia/callback');
    const ent = await ios.entitlements({ modResults: {}, modRequest: { platform: 'ios' } } as never);
    expect(ent.modResults['com.apple.developer.associated-domains']).toEqual(['applinks:notes.example.com']);
    const manifest = { manifest: { application: [{ $: { 'android:name': '.MainApplication' }, activity: [{ $: { 'android:name': '.MainActivity' } }] }] } };
    const out = await android.manifest({ modResults: manifest, modRequest: { platform: 'android' } } as never);
    const f = out.modResults.manifest.application[0].activity[0]['intent-filter'][0];
    expect(f.$['android:autoVerify']).toBe('true');
    expect(f.data[0].$).toEqual({ 'android:scheme': 'https', 'android:host': 'notes.example.com', 'android:path': '/identvia/callback' });
  });
});
