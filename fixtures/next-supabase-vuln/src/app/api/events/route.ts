import { getD1 } from '@/lib/server/d1';

// vg-expect: endpoints/unauthenticated-data-access
export async function POST(request: Request) {
  const { eventId, email } = (await request.json()) as { eventId: string; email: string };
  await getD1()
    .prepare('INSERT INTO registrations (event_id, email) VALUES (?1, ?2)')
    .bind(eventId, email)
    .run();
  return Response.json({ ok: true });
}
