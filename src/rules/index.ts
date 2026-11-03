import type { Rule } from '../core/engine/rule.ts';
import { authRouteNoRateLimitRule } from './endpoints/auth-route-no-rate-limit.rule.ts';
import { corsWildcardCredentialsRule } from './endpoints/cors-wildcard-credentials.rule.ts';
import { unauthenticatedDataAccessRule } from './endpoints/unauthenticated-data-access.rule.ts';
import { webhookWithoutSignatureRule } from './endpoints/webhook-without-signature.rule.ts';
import { clientExposedEnvRule } from './secrets/client-exposed-env.rule.ts';
import { envFileCommittedRule } from './secrets/env-file-committed.rule.ts';
import { highEntropyRule } from './secrets/high-entropy.rule.ts';
import { privateKeyRule } from './secrets/private-key.rule.ts';
import { providerKeyTestRule } from './secrets/provider-key-test.rule.ts';
import { providerKeyRule } from './secrets/provider-key.rule.ts';
import { permissivePolicyRule } from './supabase/permissive-policy.rule.ts';
import { rlsDisabledRule } from './supabase/rls-disabled.rule.ts';
import { rlsNoPoliciesRule } from './supabase/rls-no-policies.rule.ts';
import {
  securityDefinerFunctionRule,
  securityDefinerViewRule,
} from './supabase/security-definer.rule.ts';
import { serviceRoleInClientRule } from './supabase/service-role-in-client.rule.ts';

/**
 * The rule registry. This is the only list of rules; adding a rule means adding its
 * module and one line here. Core code never names a rule. See docs/adr/0006.
 *
 * There is intentionally no runtime plugin loading: the config file lives in the scanned
 * repository, which may be untrusted, and must never be able to load code.
 */
export const ALL_RULES: readonly Rule[] = [
  providerKeyRule,
  providerKeyTestRule,
  privateKeyRule,
  highEntropyRule,
  envFileCommittedRule,
  clientExposedEnvRule,
  rlsDisabledRule,
  rlsNoPoliciesRule,
  permissivePolicyRule,
  serviceRoleInClientRule,
  securityDefinerViewRule,
  securityDefinerFunctionRule,
  unauthenticatedDataAccessRule,
  corsWildcardCredentialsRule,
  authRouteNoRateLimitRule,
  webhookWithoutSignatureRule,
] as readonly Rule[];
