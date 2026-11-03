import { requireTeamMember } from '@acme/auth';
import { supabaseAdmin } from '@/lib/supabase/admin';

// Auth helper from a package VibeGuard cannot inspect: reported as unverified, low confidence.
// vg-expect: endpoints/unauthenticated-data-access
export async function GET(request: Request) {
  await requireTeamMember(request);
  const { data } = await supabaseAdmin.from('profiles').select('id, full_name');
  return Response.json(data);
}
