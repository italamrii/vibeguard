import { isRtl, type Locale } from './locale.ts';

/**
 * Bidirectional-text helpers for RTL reports (ADR-0013).
 *
 * Arabic sentences routinely contain left-to-right runs: rule ids, file names, env vars,
 * product names, code (`.env.local`, `NEXT_PUBLIC_`, `auth.uid()`, `USING (true)`). Without
 * isolation the Unicode bidi algorithm reorders their neutral characters against the Arabic
 * context: a leading dot jumps to the other end (".env" shows as "env."), parentheses flip,
 * and "a.b c" fragments reverse. Wrapping each LTR run in LEFT-TO-RIGHT ISOLATE … POP
 * DIRECTIONAL ISOLATE makes it an opaque LTR unit that cannot interact with its neighbours.
 *
 * All code points are built with String.fromCodePoint so this file contains no invisible
 * characters (see test/unit/source-hygiene.test.ts).
 */

/** LEFT-TO-RIGHT ISOLATE, FIRST STRONG ISOLATE, POP DIRECTIONAL ISOLATE (UAX #9). */
export const LRI = String.fromCodePoint(0x2066);
export const RLI = String.fromCodePoint(0x2067);
export const FSI = String.fromCodePoint(0x2068);
export const PDI = String.fromCodePoint(0x2069);

/** Isolate one known-LTR string (path, rule id, identifier). No-op for LTR locales. */
export function isolateLtr(s: string, locale: Locale): string {
  return isRtl(locale) ? `${LRI}${s}${PDI}` : s;
}

/** Isolate text of unknown direction (e.g. a user-written suppression reason). */
export function isolateAuto(s: string, locale: Locale): string {
  return isRtl(locale) ? `${FSI}${s}${PDI}` : s;
}

const STRONG_LTR = /[A-Za-z0-9\u00C0-\u024F]/;
/** Characters that may belong to an LTR token: Latin, digits, ASCII punctuation, single spaces. */
const RUN =
  /[A-Za-z0-9\u00C0-\u024F._\-\/@#$%&*+=~`'"()[\]{}<>:!?\\|^,;]+(?: [A-Za-z0-9\u00C0-\u024F._\-\/@#$%&*+=~`'"()[\]{}<>:!?\\|^,;]+)*/g;
const TRAILING_SENTENCE_PUNCT = /[.,;:!?]+$/;
const PAIRS: Readonly<Record<string, string>> = { ')': '(', ']': '[', '}': '{', '>': '<' };
const OPENERS = new Set(['(', '[', '{', '<']);

/** Trim unbalanced brackets and sentence punctuation from a run's edges. */
function trimRun(run: string): [string, string, string] {
  let lead = '';
  let body = run;
  let tail = '';
  for (let changed = true; changed && body.length > 0;) {
    changed = false;
    // Punctuation at the very end of a run ends the Arabic sentence, not the token: dots
    // inside a token ("v1.2", ".env.local") are never at the end, so they are kept.
    const t = TRAILING_SENTENCE_PUNCT.exec(body);
    if (t) {
      tail = t[0] + tail;
      body = body.slice(0, -t[0].length);
      changed = true;
    }
    const last = body.at(-1) ?? '';
    const opener = PAIRS[last];
    if (opener !== undefined && count(body, last) > count(body, opener)) {
      tail = last + tail;
      body = body.slice(0, -1);
      changed = true;
    }
    // A trailing opener ("… (") opens an Arabic parenthetical, not an LTR one.
    const end = body.at(-1) ?? '';
    if (OPENERS.has(end) && count(body, end) > count(body, closerOf(end))) {
      body = body.slice(0, -1);
      const ws = /\s*$/.exec(body)?.[0] ?? '';
      tail = ws + end + tail;
      body = body.slice(0, body.length - ws.length);
      changed = true;
    }
    const first = body[0] ?? '';
    if (OPENERS.has(first) && count(body, first) > count(body, closerOf(first))) {
      lead += first;
      body = body.slice(1);
      changed = true;
    }
  }
  return [lead, body, tail];
}

function closerOf(open: string): string {
  return open === '(' ? ')' : open === '[' ? ']' : open === '{' ? '}' : '>';
}

function count(s: string, ch: string): number {
  let n = 0;
  for (const c of s) if (c === ch) n++;
  return n;
}

/** Index of the last opener that has no matching closer after it, or -1. */
function unmatchedOpener(s: string): number {
  const stack: number[] = [];
  for (let i = 0; i < s.length; i++) {
    const c = s[i] ?? '';
    if (OPENERS.has(c)) stack.push(i);
    else if (
      PAIRS[c] !== undefined &&
      stack.length > 0 &&
      s[stack[stack.length - 1] ?? -1] === PAIRS[c]
    )
      stack.pop();
  }
  return stack.length > 0 ? (stack[stack.length - 1] ?? -1) : -1;
}

/**
 * Isolate one candidate run. Sentence punctuation that *leads* a run (": 171") belongs to the
 * Arabic sentence; a bracket opened inside the run but closed in Arabic ("171 (47 ملّي ثانية)")
 * splits it, and each side is isolated separately.
 */
function isolateRun(run: string): string {
  if (!STRONG_LTR.test(run)) return run;
  const lead0 = /^[.,;:!?]+(?=\s)|^\s+/.exec(run)?.[0] ?? '';
  if (lead0 !== '') return lead0 + isolateRun(run.slice(lead0.length));
  const [lead, body, tail] = trimRun(run);
  const cut = unmatchedOpener(body);
  if (cut > 0) {
    const left = body.slice(0, cut);
    const right = body.slice(cut);
    const ws = /\s*$/.exec(left)?.[0] ?? '';
    return `${lead}${isolateRun(left.slice(0, left.length - ws.length))}${ws}${isolateRun(right)}${tail}`;
  }
  return STRONG_LTR.test(body) ? `${lead}${LRI}${body}${PDI}${tail}` : run;
}

/**
 * Wrap every LTR run in `text` with LRI…PDI. Text already inside isolates is left alone.
 * Intended for RTL prose; safe to call on LTR text (it would isolate everything).
 */
export function isolateLtrRuns(text: string): string {
  let out = '';
  let depth = 0;
  let segment = '';
  const flush = (): void => {
    out += segment.replace(RUN, isolateRun);
    segment = '';
  };
  for (const ch of text) {
    if (ch === LRI || ch === RLI || ch === FSI) {
      if (depth === 0) flush();
      depth++;
      out += ch;
    } else if (ch === PDI && depth > 0) {
      depth--;
      out += ch;
    } else if (depth > 0) {
      out += ch;
    } else {
      segment += ch;
    }
  }
  flush();
  return out;
}

/**
 * Isolate LTR runs in a message template while leaving `{placeholders}` untouched, so the
 * caller can interpolate (and isolate) parameter values separately.
 */
export function isolateTemplate(template: string): string {
  return template
    .split(/(\{[a-zA-Z0-9_]+\})/)
    .map((part) => (/^\{[a-zA-Z0-9_]+\}$/.test(part) ? part : isolateLtrRuns(part)))
    .join('');
}

const ARABIC = /[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFC]/;

export interface BidiViolation {
  readonly line: number;
  readonly text: string;
}

/**
 * Lines of RTL Markdown where a Latin letter or digit sits outside any isolate on a line
 * that also contains Arabic. Fenced code blocks are skipped (they are laid out LTR).
 */
export function findUnisolatedLtr(markdown: string): BidiViolation[] {
  const out: BidiViolation[] = [];
  let inFence = false;
  markdown.split('\n').forEach((line, i) => {
    if (/^\s*(`{3,}|~{3,})/.test(line)) {
      inFence = !inFence;
      return;
    }
    if (inFence || !ARABIC.test(line)) return;
    let depth = 0;
    for (const ch of line) {
      if (ch === LRI || ch === RLI || ch === FSI) depth++;
      else if (ch === PDI) depth = Math.max(0, depth - 1);
      else if (depth === 0 && STRONG_LTR.test(ch)) {
        out.push({ line: i + 1, text: line });
        return;
      }
    }
  });
  return out;
}
