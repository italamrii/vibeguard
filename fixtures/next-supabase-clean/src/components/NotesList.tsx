'use client';
// Never use the service_role key here: the browser client below uses the anon key.
import { supabase } from '@/lib/supabase/client';

export function NotesList() {
  return <button onClick={() => supabase.from('notes').select('*')}>Load</button>;
}
