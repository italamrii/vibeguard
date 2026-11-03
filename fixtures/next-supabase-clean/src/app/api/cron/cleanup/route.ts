import { supabaseAdmin } from '@/lib/supabase/server';

// Vercel Cron: authenticated with CRON_SECRET.
export async function GET(request: Request) {
  if (request.headers.get('authorization') !== `Bearer ${process.env.CRON_SECRET}`) {
    return new Response('Unauthorized', { status: 401 });
  }
  await supabaseAdmin().from('notes').delete().lt('created_at', new Date(Date.now() - 864e5).toISOString());
  return Response.json({ ok: true });
}
