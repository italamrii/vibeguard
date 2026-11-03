import { createClient } from '@/lib/supabase/server-client';

export async function GET() {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) return new Response('Unauthorized', { status: 401 });
  return Response.json(user, {
    // vg-expect: endpoints/cors-wildcard-credentials
    headers: { 'Access-Control-Allow-Origin': '*' },
  });
}
