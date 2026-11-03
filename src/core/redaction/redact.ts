/**
 * Redaction primitives. See docs/adr/0005-redaction-and-evidence.md.
 *
 * `Redacted` is a branded string. Reporters only accept `Redacted` evidence, and the
 * only ways to create one are `redactSecret()` (for a known secret value) and
 * `scrubText()` (for arbitrary text such as a code snippet, which may contain secrets
 * nobody told us about). That makes "printed a raw secret" a type error rather than a
 * code-review catch.
 */

declare const redactedBrand: unique symbol;
export type Redacted = string & { readonly [redactedBrand]: true };

/** Number of leading characters of a secret that may be shown. Fixed by product requirement. */
export const VISIBLE_PREFIX = 4;
/** Secrets this short are shown as length only: four characters of an eight-character value is half of it. */
const MIN_LENGTH_FOR_PREFIX = 9;

export function redactSecret(secret: string): Redacted {
  const chars = Array.from(secret); // count code points, not UTF-16 units
  const len = chars.length;
  if (len < MIN_LENGTH_FOR_PREFIX) {
    return `…[${len} chars]` as Redacted;
  }
  return `${chars.slice(0, VISIBLE_PREFIX).join('')}…[${len} chars]` as Redacted;
}

/** Concatenate already-redacted fragments. */
export function joinRedacted(parts: readonly Redacted[], sep = ''): Redacted {
  return parts.join(sep) as Redacted;
}

/** Marker for evidence that has no textual content (e.g. "file exists"). */
export const NO_EVIDENCE = '' as Redacted;

// --- Generic scrubber -------------------------------------------------------------
//
// The scrubber is defence in depth for free-form evidence (code snippets). It does not
// know provider formats (those live in the secrets rule family); it redacts anything
// that is shaped like a credential. Over-redaction of a snippet is an acceptable cost.

const PEM_BLOCK =
  /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY-----[\s\S]{0,10000}?(?:-----END [A-Z0-9 ]{0,40}PRIVATE KEY-----|$)/g;
// scheme://user:password@host — redact the password component.
const URL_CREDENTIALS = /([a-z][a-z0-9+.-]{1,20}:\/\/[^\s:/@'"`]{1,256}:)([^\s@'"`]{1,256})(@)/gi;
// JWT-shaped: three base64url segments, the first starting with eyJ.
const JWT = /\beyJ[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{2,8192}\.[A-Za-z0-9_-]{2,4096}/g;
// Long token-ish runs. Bounded quantifier keeps this linear.
const TOKEN = /[A-Za-z0-9_\-+/=.]{20,4096}/g;

/** Shannon entropy in bits per character. */
export function shannonEntropy(s: string): number {
  if (s.length === 0) return 0;
  const counts = new Map<string, number>();
  for (const ch of s) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function looksLikeCredential(token: string): boolean {
  // Paths, dotted identifiers and URLs are common in snippets and not secrets.
  if (/^[./]/.test(token) || token.includes('//')) return false;
  if (/^[a-z]+(?:[._-][a-z]+)+$/i.test(token)) return false; // some.dotted_identifier-name
  // Identifiers (camelCase, SCREAMING_CASE) are letters-only; generated credentials of
  // 20+ characters virtually always contain a digit. Requiring one keeps code readable.
  if (!/\d/.test(token) || !/[a-z]/i.test(token)) return false;
  return shannonEntropy(token) >= 3.5;
}

/**
 * Redact credential-shaped substrings from free text and truncate to `maxLength`.
 * `knownSecrets` are redacted unconditionally (rules pass the secret they matched).
 */
export function scrubText(
  text: string,
  options: { knownSecrets?: readonly string[]; maxLength?: number } = {},
): Redacted {
  const maxLength = options.maxLength ?? 200;
  let out = text;
  for (const secret of options.knownSecrets ?? []) {
    if (secret.length > 0) out = out.split(secret).join(redactSecret(secret));
  }
  out = out.replace(PEM_BLOCK, (m) => redactSecret(m.replace(/\s+/g, '')));
  out = out.replace(
    URL_CREDENTIALS,
    (_m, pre: string, pw: string, at: string) => `${pre}${redactSecret(pw)}${at}`,
  );
  out = out.replace(JWT, (m) => redactSecret(m));
  out = out.replace(TOKEN, (m) => (looksLikeCredential(m) ? redactSecret(m) : m));
  const chars = Array.from(out);
  if (chars.length > maxLength) out = `${chars.slice(0, maxLength - 1).join('')}…`;
  return out as Redacted;
}
