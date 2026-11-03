import type { Rule } from '../core/engine/rule.ts';

/**
 * The rule registry. This is the only list of rules; adding a rule means adding its
 * module and one line here. Core code never names a rule. See docs/adr/0006.
 *
 * There is intentionally no runtime plugin loading: the config file lives in the scanned
 * repository, which may be untrusted, and must never be able to load code.
 */
export const ALL_RULES: readonly Rule[] = [];
