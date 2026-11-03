import { supabaseAdmin } from '@/lib/supabase/admin';

// vg-expect: endpoints/unauthenticated-data-access
export const GET = async () => {
  const { data } = await supabaseAdmin.from('profiles').select('id, full_name, stripe_customer_id');
  return Response.json(data);
};
