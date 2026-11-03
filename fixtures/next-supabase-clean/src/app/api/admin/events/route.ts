import { getD1 } from '@/lib/server/d1';
import { authenticateStaffRequest } from '@/lib/server/admin-auth';

export async function DELETE(request: Request) {
  const auth = await authenticateStaffRequest(request);
  if ('error' in auth) return new Response('Unauthorized', { status: 401 });
  const { id } = (await request.json()) as { id: string };
  await getD1().prepare('DELETE FROM events WHERE id = ?1').bind(id).run();
  return Response.json({ ok: true });
}
