'use client';
import { createClient } from '@supabase/supabase-js';

const supabase = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  // vg-expect: supabase/service-role-in-client
  process.env.SUPABASE_SERVICE_ROLE_KEY!,
);

export async function listUsers() {
  return supabase.auth.admin.listUsers();
}
