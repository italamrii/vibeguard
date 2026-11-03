import { createClient } from './supabase/server-client';

type Handler = (req: Request, userId: string) => Promise<Response>;

// Auth wrapper that really checks (followed one level by VibeGuard).
export function withUser(handler: Handler) {
  return async (req: Request) => {
    const supabase = await createClient();
    const {
      data: { user },
    } = await supabase.auth.getUser();
    if (!user) return new Response('Unauthorized', { status: 401 });
    return handler(req, user.id);
  };
}
