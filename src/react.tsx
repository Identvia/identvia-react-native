import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from 'react';
import { ActivityIndicator, Pressable, StyleSheet, Text, View, type StyleProp, type ViewStyle } from 'react-native';
import { IdentviaNativeClient, type IdentviaNativeConfig, type NativeSession, type SignInOptions } from './client';
import { expoAuthSession, expoCrypto, expoSecureStorage } from './expo';
import { CancelledError } from './errors';
import type { IdTokenClaims } from './idtoken';

export interface IdentviaContextValue {
  client: IdentviaNativeClient;
  isLoading: boolean;
  isAuthenticated: boolean;
  user: IdTokenClaims | null;
  error: Error | null;
  signIn(o?: SignInOptions): Promise<NativeSession | null>;
  signOut(o?: { federated?: boolean }): Promise<void>;
  getAccessToken(force?: boolean): Promise<string>;
}

const Ctx = createContext<IdentviaContextValue | null>(null);

export type IdentviaProviderProps = Omit<IdentviaNativeConfig, 'crypto' | 'authSession' | 'storage'> & Partial<Pick<IdentviaNativeConfig, 'crypto' | 'authSession' | 'storage'>> & { children?: ReactNode; client?: IdentviaNativeClient };

/** Uses the Expo adapters by default; pass your own (e.g. react-native-app-auth based) to replace them. */
export function IdentviaProvider({ children, client: given, ...cfg }: IdentviaProviderProps) {
  const ref = useRef<IdentviaNativeClient | null>(given ?? null);
  if (!ref.current) ref.current = new IdentviaNativeClient({ crypto: expoCrypto, authSession: expoAuthSession, storage: expoSecureStorage, ...cfg });
  const client = ref.current;
  const [state, setState] = useState<{ isLoading: boolean; user: IdTokenClaims | null; error: Error | null }>({ isLoading: true, user: null, error: null });
  useEffect(() => {
    const off = client.onChange((s) => setState({ isLoading: false, user: s?.user ?? null, error: null }));
    client.getSession().then((s) => setState({ isLoading: false, user: s?.user ?? null, error: null }), (error) => setState({ isLoading: false, user: null, error }));
    return off;
  }, [client]);
  const signIn = useCallback(async (o?: SignInOptions) => {
    try { return await client.signIn(o); } catch (e) {
      if (e instanceof CancelledError) return null;
      setState((s) => ({ ...s, error: e as Error }));
      throw e;
    }
  }, [client]);
  const signOut = useCallback((o?: { federated?: boolean }) => client.signOut(o), [client]);
  const getAccessToken = useCallback((force?: boolean) => client.getAccessToken(force), [client]);
  const value = useMemo<IdentviaContextValue>(() => ({ client, ...state, isAuthenticated: !!state.user, signIn, signOut, getAccessToken }), [client, state, signIn, signOut, getAccessToken]);
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

export function useIdentvia(): IdentviaContextValue {
  const v = useContext(Ctx);
  if (!v) throw new Error('useIdentvia() must be used inside <IdentviaProvider>.');
  return v;
}

const LABELS = { signin: 'Sign in with Identvia', continue: 'Continue with Identvia', signup: 'Sign up with Identvia' } as const;
const THEMES = {
  light: { bg: '#ffffff', border: '#d4d4d8', fg: '#18181b', pressed: '#f4f4f5' },
  dark: { bg: '#18181b', border: '#3f3f46', fg: '#ffffff', pressed: '#27272a' },
  brand: { bg: '#4b4acf', border: '#4b4acf', fg: '#ffffff', pressed: '#3d3cb4' },
} as const;
const SIZES = { small: { h: 32, px: 12, fs: 13, icon: 16, r: 6 }, medium: { h: 40, px: 16, fs: 14, icon: 20, r: 8 }, large: { h: 48, px: 20, fs: 16, icon: 22, r: 10 } } as const;

/** The Identvia mark drawn with plain Views (no SVG dependency): brand square, dot and check. */
function Mark({ size }: { size: number }) {
  const u = size / 28;
  return (
    <View style={{ width: size, height: size, borderRadius: 8 * u, backgroundColor: '#4B4ACF', overflow: 'hidden' }} accessibilityElementsHidden importantForAccessibility="no-hide-descendants">
      <View style={{ position: 'absolute', left: 7.15 * u, top: 6.15 * u, width: 4.2 * u, height: 4.2 * u, borderRadius: 2.1 * u, backgroundColor: '#fff' }} />
      <View style={{ position: 'absolute', left: 8.2 * u, top: 15.3 * u, width: 7.3 * u, height: 2.6 * u, borderRadius: 1.3 * u, backgroundColor: '#fff', transform: [{ rotate: '57deg' }] }} />
      <View style={{ position: 'absolute', left: 11.2 * u, top: 12.6 * u, width: 13.9 * u, height: 2.6 * u, borderRadius: 1.3 * u, backgroundColor: '#fff', transform: [{ rotate: '-55deg' }] }} />
    </View>
  );
}

export interface SignInWithIdentviaProps {
  theme?: keyof typeof THEMES;
  size?: keyof typeof SIZES;
  shape?: 'rect' | 'rounded' | 'pill';
  text?: keyof typeof LABELS;
  fullWidth?: boolean;
  options?: SignInOptions;
  onPress?: () => void;
  style?: StyleProp<ViewStyle>;
  disabled?: boolean;
}

export function SignInWithIdentvia({ theme = 'light', size = 'medium', shape = 'rounded', text = 'signin', fullWidth, options, onPress, style, disabled }: SignInWithIdentviaProps) {
  const ctx = useContext(Ctx);
  const [busy, setBusy] = useState(false);
  const t = THEMES[theme], s = SIZES[size];
  const radius = shape === 'pill' ? s.h / 2 : shape === 'rect' ? 4 : s.r;
  const label = LABELS[text];
  const press = async () => {
    if (onPress) return onPress();
    if (!ctx || busy) return;
    setBusy(true);
    try { await ctx.signIn(options); } catch { /* surfaced via ctx.error */ } finally { setBusy(false); }
  };
  return (
    <Pressable
      accessibilityRole="button" accessibilityLabel={label} accessibilityState={{ disabled: !!disabled, busy }}
      disabled={disabled || busy} onPress={press}
      style={({ pressed }) => [styles.btn, { height: s.h, paddingHorizontal: s.px, borderRadius: radius, backgroundColor: pressed ? t.pressed : t.bg, borderColor: t.border, opacity: disabled ? 0.5 : 1 }, fullWidth && styles.full, style]}
    >
      {busy ? <ActivityIndicator color={t.fg} /> : <Mark size={s.icon} />}
      <Text style={{ color: t.fg, fontSize: s.fs, fontWeight: '600', marginLeft: 10 }} numberOfLines={1}>{label}</Text>
    </Pressable>
  );
}

const styles = StyleSheet.create({
  btn: { flexDirection: 'row', alignItems: 'center', justifyContent: 'center', borderWidth: 1, alignSelf: 'flex-start' },
  full: { alignSelf: 'stretch' },
});
