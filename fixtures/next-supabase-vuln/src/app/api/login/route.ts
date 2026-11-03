import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import { supabaseAdmin } from '@/lib/supabase/admin';

// vg-expect: endpoints/auth-route-no-rate-limit
export async function POST(request: Request) {
  const { email, password } = (await request.json()) as { email: string; password: string };
  const { data: user } = await supabaseAdmin.from('profiles').select('id, password_hash').eq('email', email).single();
  if (!user || !(await bcrypt.compare(password, user.password_hash))) return new Response('Invalid', { status: 401 });
  return Response.json({ token: jwt.sign({ sub: user.id }, process.env.JWT_SECRET!) });
}
