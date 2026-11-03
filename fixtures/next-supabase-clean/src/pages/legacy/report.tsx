import { createClient } from '@supabase/supabase-js';

// Pages Router: getServerSideProps runs on the server only and is stripped from the bundle.
export async function getServerSideProps() {
  const admin = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
  const { count } = await admin.from('notes').select('*', { count: 'exact', head: true });
  return { props: { count: count ?? 0 } };
}

export default function Report({ count }: { count: number }) {
  return <p>{count} notes</p>;
}
