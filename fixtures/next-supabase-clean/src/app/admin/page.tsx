// Server Component (App Router default): the service-role client never reaches the browser.
import { supabaseAdmin } from '@/lib/supabase/server';

export default async function AdminPage() {
  const { data } = await supabaseAdmin().from('notes').select('id');
  return <p>{data?.length ?? 0} notes</p>;
}
