import { NextResponse, type NextRequest } from 'next/server';
import { getToken } from 'next-auth/jwt';

// Enforces auth, but the matcher only covers /admin pages, not /api/admin routes.
export async function middleware(request: NextRequest) {
  const token = await getToken({ req: request });
  if (!token) return NextResponse.redirect(new URL('/login', request.url));
  return NextResponse.next();
}

export const config = { matcher: ['/admin/:path*'] };
