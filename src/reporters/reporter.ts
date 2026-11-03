import type { ScanResult } from '../core/engine/engine.ts';
import type { RuleMeta } from '../core/engine/rule.ts';
import type { Diagnostic, Finding } from '../core/findings/finding.ts';
import { SEVERITIES, type Confidence, type Severity } from '../core/findings/severity.ts';
import { isolateTemplate } from '../i18n/bidi.ts';
import { interpolate, isRtl, type Locale } from '../i18n/locale.ts';
import { UI } from '../i18n/ui.ts';
import { sanitizeUntrusted } from './text-safety.ts';

export interface ReportOptions {
  readonly locale: Locale;
  readonly color: boolean;
  readonly toolVersion: string;
  readonly failOn: Severity | 'none';
  readonly minConfidence: Confidence;
}

export interface Reporter {
  readonly format: string;
  render(result: ScanResult, opts: ReportOptions): string;
}

export const DOCS_BASE_URL = 'https://github.com/italamrii/vibeguard/blob/main/docs/rules';

export function ruleDocsUrl(ruleId: string): string {
  return `${DOCS_BASE_URL}/${ruleId}.md`;
}

export function ruleIndex(result: ScanResult): ReadonlyMap<string, RuleMeta> {
  return new Map(result.rules.map((r) => [r.id, r]));
}

/**
 * Render a finding's message in `locale`. Interpolated params are untrusted (they come
 * from scanned code), so they are sanitised before `wrap` formats them.
 */
export function renderMessage(
  finding: Finding,
  meta: RuleMeta | undefined,
  locale: Locale,
  wrap: (value: string) => string = (v) => v,
): string {
  const template = meta?.messages[finding.messageId]?.[locale];
  if (template === undefined) return finding.messageId;
  // RTL: isolate LTR runs in the template itself (".env", "RLS", "getUser()"); params are
  // isolated by `wrap`.
  const t = isRtl(locale) ? isolateTemplate(template) : template;
  return interpolate(t, finding.params, (v) => wrap(sanitizeUntrusted(v)));
}

export function renderDiagnostic(
  d: Diagnostic,
  locale: Locale,
  wrap: (value: string) => string = (v) => v,
): string {
  const ui = UI[locale];
  const params: Record<string, string | number> = { ...d.params };
  const problem = d.params['problem'];
  if (
    d.code === 'invalid-suppression' &&
    typeof problem === 'string' &&
    problem in ui.suppressionProblems
  ) {
    params['problem'] = ui.suppressionProblems[problem as keyof typeof ui.suppressionProblems];
  }
  const template = isRtl(locale) ? isolateTemplate(ui.diagnostics[d.code]) : ui.diagnostics[d.code];
  return interpolate(template, params, (v) => wrap(sanitizeUntrusted(v)));
}

export interface Counts {
  readonly bySeverity: Readonly<Record<Severity, number>>;
  readonly active: number;
  readonly suppressed: number;
}

export function countFindings(findings: readonly Finding[]): Counts {
  const bySeverity: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  let suppressed = 0;
  for (const f of findings) {
    if (f.suppression) suppressed++;
    else bySeverity[f.severity]++;
  }
  const active = SEVERITIES.reduce((n, s) => n + bySeverity[s], 0);
  return { bySeverity, active, suppressed };
}

/**
 * Diagnostics meaning part of the project could not be analysed. When any is present,
 * no reporter may present the result as clean.
 */
const PARTIAL_COVERAGE_CODES: ReadonlySet<string> = new Set([
  'parse-failed',
  'no-migrations',
  'dynamic-sql',
]);

export function isPartialCoverage(result: ScanResult): boolean {
  return result.diagnostics.some((d) => PARTIAL_COVERAGE_CODES.has(d.code));
}

export function activeFindings(result: ScanResult): readonly Finding[] {
  return result.findings.filter((f) => !f.suppression);
}

/** Rules that have at least one active finding, in first-appearance order. */
export function rulesWithFindings(result: ScanResult): readonly RuleMeta[] {
  const idx = ruleIndex(result);
  const seen = new Set<string>();
  const out: RuleMeta[] = [];
  for (const f of activeFindings(result)) {
    if (seen.has(f.ruleId)) continue;
    seen.add(f.ruleId);
    const m = idx.get(f.ruleId);
    if (m) out.push(m);
  }
  return out;
}

/** File paths come from the scanned project and are untrusted, like any other content. */
export function formatLocation(f: Finding): string {
  return `${sanitizeUntrusted(f.location.file)}:${f.location.line}:${f.location.column}`;
}
