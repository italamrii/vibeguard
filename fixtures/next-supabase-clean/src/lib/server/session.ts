import { cookies } from 'next/headers';
import { getD1 } from './d1';

// Project-specific auth helper: resolves the signed-in member from the session cookie.
export async function getMemberUser() {
  const sid = (await cookies()).get('sid')?.value;
  if (!sid) return null;
  return getD1().prepare('SELECT user_id FROM sessions WHERE id = ?1 AND expires_at > unixepoch()').bind(sid).first();
}
