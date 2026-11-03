import { getD1 } from './d1';

// Project-specific admin guard (name chosen by the app, not by a framework).
export async function authenticateStaffRequest(request: Request) {
  const token = request.headers.get('authorization')?.replace('Bearer ', '');
  if (!token) return { error: 'unauthorized' as const };
  const row = await getD1().prepare('SELECT user_id FROM staff_tokens WHERE token = ?1').bind(token).first();
  return row ? { userId: row.user_id } : { error: 'unauthorized' as const };
}
