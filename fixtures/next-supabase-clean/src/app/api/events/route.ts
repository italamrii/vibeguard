import { getD1 } from '@/lib/server/d1';
import { getMemberUser } from '@/lib/server/session';

export async function POST(request: Request) {
  const member = await getMemberUser();
  if (!member) return new Response('Unauthorized', { status: 401 });
  const { eventId } = (await request.json()) as { eventId: string };
  await getD1().prepare('INSERT INTO registrations (event_id, user_id) VALUES (?1, ?2)').bind(eventId, member.user_id).run();
  return Response.json({ ok: true });
}
