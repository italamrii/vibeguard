import { isRtl, type Locale } from './locale.ts';

/** LEFT-TO-RIGHT ISOLATE … POP DIRECTIONAL ISOLATE (Unicode 6.3, UAX #9). */
export const LRI = String.fromCodePoint(0x2066);
export const PDI = String.fromCodePoint(0x2069);

/**
 * Isolate a left-to-right run (path, rule id, identifier) inside right-to-left prose so
 * its punctuation and digits are not reordered. No-op for LTR locales.
 */
export function isolateLtr(s: string, locale: Locale): string {
  return isRtl(locale) ? `${LRI}${s}${PDI}` : s;
}
