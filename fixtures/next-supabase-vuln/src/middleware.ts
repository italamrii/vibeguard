import { type NextRequest } from 'next/server';
import { updateSession } from '@/lib/supabase/middleware';

// Refreshes the auth cookie on every request. It does NOT block anonymous requests.
export async function middleware(request: NextRequest) {
  return updateSession(request);
}

export const config = { matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'] };
