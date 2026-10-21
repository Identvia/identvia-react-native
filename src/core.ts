// Platform-neutral core (no Expo/React Native imports). Bring your own AuthSessionAdapter, e.g. react-native-app-auth.
export * from './errors';
export { IdentviaNativeClient, DEFAULT_ISSUER, assertNativeRedirect, isSameRedirect, type IdentviaNativeConfig, type AuthSessionAdapter, type SecureStorageAdapter, type NativeSession, type Tokens, type SignInOptions, type AuthorizationDetail } from './client';
export { webCryptoProvider, codeChallenge, type CryptoProvider } from './crypto';
export { validateIdToken, decodeJwt, ALLOWED_ALGS, type IdTokenClaims, type Jwk } from './idtoken';
