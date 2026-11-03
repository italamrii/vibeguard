'use server';
import { supabaseAdmin } from '@/lib/supabase/admin';
import { createClient } from '@/lib/supabase/server-client';

// Server actions are public POST endpoints.
// vg-expect: endpoints/unauthenticated-data-access
export async function deleteNote(id: string) {
  await supabaseAdmin.from('notes').delete().eq('id', id);
}

export async function updateProfile(fullName: string) {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) throw new Error('Not signed in');
  await supabase.from('profiles').update({ full_name: fullName }).eq('id', user.id);
}
