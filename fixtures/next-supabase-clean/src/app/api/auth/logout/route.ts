import { cookies } from 'next/headers';
import { getD1 } from '@/lib/server/d1';

// Logout acts only on the caller's own session cookie: no prior auth check is needed.
export async function POST() {
  const sid = (await cookies()).get('sid')?.value;
  if (sid) await getD1().prepare('DELETE FROM sessions WHERE id = ?1').bind(sid).run();
  return Response.json({ ok: true });
}
