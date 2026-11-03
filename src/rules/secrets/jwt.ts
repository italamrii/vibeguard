/** Locate JWT-shaped tokens. Bounded quantifiers keep this linear. */
export const JWT_PATTERN =
  /\beyJ[A-Za-z0-9_-]{8,2048}\.eyJ[A-Za-z0-9_-]{8,8192}\.[A-Za-z0-9_-]{16,1024}/g;

/**
 * Decode a JWT payload without verifying it (we only need its claims to classify it).
 * Returns undefined for anything that does not decode to a JSON object.
 */
export function decodeJwtPayload(token: string): Record<string, unknown> | undefined {
  const part = token.split('.')[1];
  if (part === undefined) return undefined;
  try {
    const json = Buffer.from(part, 'base64url').toString('utf8');
    const parsed: unknown = JSON.parse(json);
    return typeof parsed === 'object' && parsed !== null && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : undefined;
  } catch {
    return undefined;
  }
}

export type SupabaseJwtRole = 'service_role' | 'anon' | 'authenticated' | 'other';

/**
 * Classify a Supabase project key. Supabase legacy API keys are JWTs with
 * `iss: "supabase"` and a `role` claim. The anon key is public by design; the
 * service_role key bypasses Row Level Security entirely.
 */
export function supabaseJwtRole(token: string): SupabaseJwtRole | undefined {
  const claims = decodeJwtPayload(token);
  if (!claims) return undefined;
  const role = claims['role'];
  const looksSupabase =
    claims['iss'] === 'supabase' ||
    (typeof claims['iss'] === 'string' && claims['iss'].includes('supabase')) ||
    typeof claims['ref'] === 'string';
  if (!looksSupabase && role !== 'service_role') return undefined;
  if (role === 'service_role' || role === 'anon' || role === 'authenticated') return role;
  return 'other';
}
