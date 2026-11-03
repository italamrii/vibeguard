export const config = {
  appName: 'Acme Notes',
  passwordMinLength: 12,
  tokenStorageKey: 'acme-auth-token-v2',
  apiKeyHeader: 'x-api-key',
  sessionTokenCookieName: 'acme_session_2024',
  secretsDocsUrl: 'https://supabase.com/docs/guides/functions/secrets',
  resetPasswordPath: '/auth/reset-password',
  buildHash: '{{FAKE:hex40:build}}',
  passwordPattern: '^(?=.*[A-Z])(?=.*\\d).{12,}$',
};

export const messages = {
  tokenExpired: 'Your session token has expired. Please sign in again.',
  passwordHint: 'Use at least 12 characters, including a number.',
  apiKeyMissing: 'API key missing',
};
