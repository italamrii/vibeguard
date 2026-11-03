/**
 * Inline suppression comments. See docs/adr/0004-suppression-design.md.
 *
 *   // vibeguard-ignore-next-line <rule-id>[, <rule-id>…] -- <reason>
 *   // vibeguard-ignore-line <rule-id> -- <reason>
 *   // vibeguard-ignore-file <rule-id> -- <reason>
 *
 * The marker is recognised inside any comment syntax (`//`, `/* *\/`, `#`, `--`,
 * `{/* *\/}`, `<!-- -->`) because we match the token on the raw line. A directive without
 * a reason of at least MIN_REASON_LENGTH characters, or with no / unknown rule ids, is
 * invalid: it suppresses nothing and is reported.
 */

export const SUPPRESSION_TOKEN = 'vibeguard-ignore-';
export const MIN_REASON_LENGTH = 10;

export type DirectiveKind = 'line' | 'next-line' | 'file';

export interface SuppressionDirective {
  readonly kind: DirectiveKind;
  readonly ruleIds: readonly string[];
  readonly reason: string;
  /** Line of the comment itself. */
  readonly line: number;
  /** Line the directive applies to; 0 for file-level directives. */
  readonly targetLine: number;
}

export interface InvalidDirective {
  readonly line: number;
  readonly problem: 'missing-reason' | 'reason-too-short' | 'missing-rule-id' | 'unknown-rule-id';
  readonly detail: string;
}

export interface ParsedSuppressions {
  readonly directives: readonly SuppressionDirective[];
  readonly invalid: readonly InvalidDirective[];
}

const DIRECTIVE = /vibeguard-ignore-(next-line|line|file)\b(.*)$/;
const RULE_ID = /^[a-z][a-z0-9-]*\/[a-z][a-z0-9-]*$/;

/** Strip trailing comment terminators: `*\/`, `*\/}`, `-->`. */
function stripCommentTail(s: string): string {
  return s.replace(/\s*(?:\*\/\s*\}?|-->)\s*$/, '').trim();
}

export function parseSuppressions(
  lines: readonly string[],
  knownRuleIds: ReadonlySet<string>,
): ParsedSuppressions {
  const directives: SuppressionDirective[] = [];
  const invalid: InvalidDirective[] = [];
  const directiveLines = new Set<number>();

  // First pass: find directive lines so `next-line` can skip stacked directives.
  const raw: { kind: DirectiveKind; rest: string; line: number }[] = [];
  lines.forEach((text, i) => {
    if (!text.includes(SUPPRESSION_TOKEN)) return;
    const m = DIRECTIVE.exec(text);
    if (!m) return;
    const line = i + 1;
    directiveLines.add(line);
    raw.push({ kind: m[1] as DirectiveKind, rest: m[2] ?? '', line });
  });

  for (const { kind, rest, line } of raw) {
    const body = stripCommentTail(rest);
    const sep = body.search(/(^|\s)--(\s|$)/);
    const idsPart = (sep === -1 ? body : body.slice(0, sep)).trim();
    const reason =
      sep === -1
        ? ''
        : body
            .slice(sep)
            .replace(/^\s*--\s*/, '')
            .trim();
    const ruleIds = idsPart
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter((s) => s.length > 0);

    if (ruleIds.length === 0) {
      invalid.push({ line, problem: 'missing-rule-id', detail: '' });
      continue;
    }
    const bad = ruleIds.find((id) => !RULE_ID.test(id) || !knownRuleIds.has(id));
    if (bad !== undefined) {
      invalid.push({ line, problem: 'unknown-rule-id', detail: bad });
      continue;
    }
    if (reason.length === 0) {
      invalid.push({ line, problem: 'missing-reason', detail: '' });
      continue;
    }
    if (Array.from(reason).length < MIN_REASON_LENGTH) {
      invalid.push({ line, problem: 'reason-too-short', detail: reason });
      continue;
    }

    let targetLine = 0;
    if (kind === 'line') targetLine = line;
    else if (kind === 'next-line') {
      targetLine = line + 1;
      while (directiveLines.has(targetLine)) targetLine++;
    }
    directives.push({ kind, ruleIds, reason, line, targetLine });
  }
  return { directives, invalid };
}

/** Find the directive that suppresses `ruleId` at `line`, if any. */
export function findSuppression(
  parsed: ParsedSuppressions,
  ruleId: string,
  line: number,
): SuppressionDirective | undefined {
  return parsed.directives.find(
    (d) => d.ruleIds.includes(ruleId) && (d.kind === 'file' || d.targetLine === line),
  );
}
