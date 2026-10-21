import { useState } from 'react';
import { Button, SafeAreaView, StyleSheet, Text, View } from 'react-native';
import { IdentviaProvider, SignInWithIdentvia, useIdentvia, maybeCompleteAuthSession } from '@identvia/react-native';

maybeCompleteAuthSession();

function Home() {
  const { isLoading, user, error, signOut, client } = useIdentvia();
  const [info, setInfo] = useState('');
  if (isLoading) return <Text>Loading…</Text>;
  if (!user) {
    return (
      <View style={styles.center}>
        <Text style={styles.h1}>Notes</Text>
        <SignInWithIdentvia theme="dark" size="large" fullWidth />
        {error ? <Text style={styles.err}>{error.message}</Text> : null}
      </View>
    );
  }
  return (
    <View style={styles.center}>
      <Text style={styles.h1}>Hi {user.name ?? user.email}</Text>
      <Text selectable>Your app-specific ID: {user.sub}</Text>
      <Button title="Call userinfo" onPress={async () => setInfo(JSON.stringify(await client.userinfo(), null, 2))} />
      <Button title="Sign out" onPress={() => signOut()} />
      <Text selectable>{info}</Text>
    </View>
  );
}

export default function App() {
  return (
    <IdentviaProvider
      clientId={process.env.EXPO_PUBLIC_IDENTVIA_CLIENT_ID ?? 'oid_your_public_client_id'}
      redirectUri="com.example.identvianotes:/oauth/identvia"
      scopes={['email', 'profile', 'offline_access']}
    >
      <SafeAreaView style={{ flex: 1 }}><Home /></SafeAreaView>
    </IdentviaProvider>
  );
}

const styles = StyleSheet.create({
  center: { flex: 1, padding: 24, gap: 16, justifyContent: 'center' },
  h1: { fontSize: 28, fontWeight: '700' },
  err: { color: '#dc2626' },
});
