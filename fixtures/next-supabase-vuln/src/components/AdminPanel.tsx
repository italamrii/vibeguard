'use client';
// vg-expect: supabase/service-role-in-client
import { supabaseAdmin } from '@/lib/supabase/admin';

export function AdminPanel({ userId }: { userId: string }) {
  return <button onClick={() => supabaseAdmin.auth.admin.deleteUser(userId)}>Delete user</button>;
}
