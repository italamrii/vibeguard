import { createClient } from '@supabase/supabase-js';

const SUPABASE_URL = 'https://{{FAKE:supabase_ref:proj}}.supabase.co';
// vg-expect: secrets/provider-key
const SERVICE_ROLE_KEY = '{{FAKE:supabase_service_jwt:proj}}';

export const supabaseAdmin = createClient(SUPABASE_URL, SERVICE_ROLE_KEY);
