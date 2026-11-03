'use server';
import { createClient } from '@/lib/supabase/server-client';

// Not exported, so not an endpoint; the auth check inside it protects every caller.
async function currentUserOrThrow() {
  const supabase = await createClient();
  const {
    data: { user },
  } = await supabase.auth.getUser();
  if (!user) throw new Error('Not signed in');
  return { supabase, user };
}

export async function deleteNote(id: string) {
  const { supabase, user } = await currentUserOrThrow();
  await supabase.from('notes').delete().eq('id', id).eq('owner', user.id);
}
