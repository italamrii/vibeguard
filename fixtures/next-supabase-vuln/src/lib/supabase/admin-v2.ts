import { createClient } from '@supabase/supabase-js';

// New-style Supabase secret key (sb_secret_...), hardcoded.
export const admin = createClient(
  process.env.NEXT_PUBLIC_SUPABASE_URL!,
  // vg-expect: secrets/provider-key
  '{{FAKE:supabase_secret:proj}}',
);
