import { createHash } from 'node:crypto';

/**
 * Fingerprint = sha256(ruleId, file, key, occurrence). It deliberately excludes line
 * numbers so that unrelated edits above a finding do not make GitHub code scanning treat
 * it as a new alert. `occurrence` disambiguates identical keys within one file.
 */
export function fingerprint(ruleId: string, file: string, key: string, occurrence: number): string {
  return createHash('sha256')
    .update(ruleId)
    .update('\0')
    .update(file)
    .update('\0')
    .update(key)
    .update('\0')
    .update(String(occurrence))
    .digest('hex')
    .slice(0, 32);
}
