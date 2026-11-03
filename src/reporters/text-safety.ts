/**
 * Everything printed from the scanned project (evidence, identifiers, table names) is
 * untrusted. Before it reaches a terminal or document we neutralise:
 *  - C0/C1 control characters, including ESC, which would let scanned code inject ANSI
 *    sequences (clear screen, rewrite earlier lines, set window title);
 *  - Unicode bidirectional controls, which would let it visually reorder a report line
 *    ("Trojan Source", CVE-2021-42574).
 * Characters are replaced with visible `<U+XXXX>` escapes so the reader can see them.
 */

// eslint-disable-next-line no-control-regex -- matching control characters is the point of this regex
const CONTROL = /[\u0000-\u0008\u000b-\u001f\u007f-\u009f]/g;
const BIDI = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g;
const NEWLINES = /[\r\n\t\u2028\u2029]+/g;

function escapeCodePoint(ch: string): string {
  return `<U+${(ch.codePointAt(0) ?? 0).toString(16).toUpperCase().padStart(4, '0')}>`;
}

export function sanitizeUntrusted(s: string): string {
  return s.replace(NEWLINES, ' ').replace(CONTROL, escapeCodePoint).replace(BIDI, escapeCodePoint);
}
