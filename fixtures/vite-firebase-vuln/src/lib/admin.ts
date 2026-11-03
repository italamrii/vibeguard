import { createClient } from '@supabase/supabase-js';

export const admin = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  // vg-expect: supabase/service-role-in-client
  import.meta.env.SUPABASE_SERVICE_ROLE_KEY,
);
