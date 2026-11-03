import type { ScanResult } from '../core/engine/engine.ts';
import type { RuleMeta } from '../core/engine/rule.ts';
import type { Finding } from '../core/findings/finding.ts';
import { SEVERITIES } from '../core/findings/severity.ts';
import { isolateAuto, isolateLtrRuns, LRI, PDI } from '../i18n/bidi.ts';
import { interpolate, isRtl, type Locale } from '../i18n/locale.ts';
import { UI } from '../i18n/ui.ts';
import {
  activeFindings,
  countFindings,
  isPartialCoverage,
  renderDiagnostic,
  renderMessage,
  ruleDocsUrl,
  ruleIndex,
  rulesWithFindings,
  type Reporter,
  type ReportOptions,
} from './reporter.ts';
import { sanitizeUntrusted } from './text-safety.ts';

/**
 * Inline code span that is safe for any content: the fence is longer than the longest
 * backtick run inside, and content is padded when it starts/ends with a backtick.
 */
export function mdCode(raw: string): string {
  const s = sanitizeUntrusted(raw);
  const longest = Math.max(0, ...Array.from(s.matchAll(/`+/g), (m) => m[0].length));
  const fence = '`'.repeat(longest + 1);
  const pad = s.startsWith('`') || s.endsWith('`') || s.length === 0 ? ' ' : '';
  return `${fence}${pad}${s}${pad}${fence}`;
}

/** Escape Markdown/HTML metacharacters in trusted prose that we did not author as Markdown. */
function mdText(s: string): string {
  return s.replace(/[\\`*_[\]<>|#]/g, (c) => `\\${c}`);
}

/** Fenced block whose fence cannot be closed early by the content. */
function mdFence(code: string, lang: string): string {
  const longest = Math.max(2, ...Array.from(code.matchAll(/`{3,}/g), (m) => m[0].length));
  const fence = '`'.repeat(longest + 1);
  return `${fence}${lang}\n${code.replace(/\n+$/, '')}\n${fence}`;
}

/** Markdown "how to fix" section for one rule; shared with SARIF `help.markdown`. */
export function ruleHelpMarkdown(m: RuleMeta, locale: Locale, headingLevel = 3): string[] {
  const ui = UI[locale];
  const rtl = isRtl(locale);
  const prose = (s: string): string => (rtl ? isolateLtrRuns(s) : s);
  const code = (s: string): string => (rtl ? `${LRI}${mdCode(s)}${PDI}` : mdCode(s));
  const block = (body: string, lang: string): string =>
    rtl ? `<div dir="ltr">\n\n${mdFence(body, lang)}\n\n</div>` : mdFence(body, lang);
  const link = (u: string): string => (rtl ? `${LRI}<${u}>${PDI}` : `<${u}>`);
  const r = m.docs.remediation;
  const refs = [ruleDocsUrl(m.id), ...m.references];
  return [
    `${'#'.repeat(headingLevel)} ${code(m.id)} ${prose(m.docs.title[locale])}`,
    '',
    prose(m.docs.summary[locale]),
    '',
    prose(r.text[locale]),
    '',
    `**${prose(ui.vulnerable)}**`,
    '',
    block(r.vulnerable, r.codeLanguage),
    '',
    `**${prose(ui.fixed)}**`,
    '',
    block(r.fixed, r.codeLanguage),
    '',
    `${prose(ui.references)}: ${refs.map(link).join(' · ')}`,
    '',
  ];
}

/**
 * RTL-safe Markdown (ADR-0013). For RTL locales:
 *  - the whole report is wrapped in <div dir="rtl"> so GitHub lays prose out right-to-left;
 *  - every code block is wrapped in <div dir="ltr"> so code keeps LTR layout;
 *  - every inline LTR token (path, rule id, identifier) is a code span bracketed by
 *    LRI/PDI isolates *outside* the backticks, so copy-pasting the code stays clean;
 *  - every LTR run inside Arabic prose (".env", "Row Level Security", "getUser()", numbers,
 *    URLs) is isolated by isolateLtrRuns; user-written text (suppression reasons) is
 *    isolated with FSI because its direction is unknown.
 * A test fails on any unisolated Latin character on a line that contains Arabic.
 */
export const markdownReporter: Reporter = {
  format: 'markdown',
  render(result: ScanResult, opts: ReportOptions): string {
    const { locale } = opts;
    const ui = UI[locale];
    const rtl = isRtl(locale);
    const prose = (s: string): string => (rtl ? isolateLtrRuns(s) : s);
    const code = (s: string): string => (rtl ? `${LRI}${mdCode(s)}${PDI}` : mdCode(s));
    const meta = ruleIndex(result);
    const counts = countFindings(result.findings);
    const out: string[] = [];

    if (rtl) out.push('<div dir="rtl">', '');
    out.push(`# ${prose(ui.reportTitle)}`, '', `> ${prose(ui.ownCodeNotice)}`, '');
    if (!result.complete) out.push(`> [!WARNING]`, `> ${prose(ui.incomplete)}`, '');
    if (isPartialCoverage(result)) out.push(`> [!WARNING]`, `> ${prose(ui.partialCoverage)}`, '');

    out.push(`## ${prose(ui.summary)}`, '');
    out.push(`| ${SEVERITIES.map((s) => prose(ui.severity[s])).join(' | ')} |`);
    out.push('|---|---|---|---|');
    out.push(`| ${SEVERITIES.map((s) => prose(String(counts.bySeverity[s]))).join(' | ')} |`, '');
    const metaLines = [
      interpolate(ui.filesScanned, { count: result.filesScanned, ms: result.durationMs }),
    ];
    if (counts.suppressed > 0)
      metaLines.push(interpolate(ui.suppressedCount, { count: counts.suppressed }));
    if (result.belowConfidenceThreshold > 0) {
      metaLines.push(
        interpolate(ui.belowThreshold, {
          count: result.belowConfidenceThreshold,
          threshold: ui.confidence[opts.minConfidence],
        }),
      );
    }
    out.push(metaLines.map(prose).join('  \n'), '');

    const findings = activeFindings(result);
    if (findings.length === 0) {
      out.push(prose(isPartialCoverage(result) ? ui.noFindingsPartial : ui.noFindings), '');
    } else {
      findings.forEach((f, i) => out.push(...renderFinding(f, i + 1)));
      out.push(`## ${prose(ui.howToFix)}`, '');
      for (const m of rulesWithFindings(result)) out.push(...ruleHelpMarkdown(m, locale));
    }

    const suppressed = result.findings.filter((f) => f.suppression);
    if (suppressed.length > 0) {
      out.push(`## ${prose(ui.suppressedTitle)}`, '');
      for (const f of suppressed) {
        const reason = mdText(sanitizeUntrusted(f.suppression?.reason ?? ''));
        out.push(
          `- ${code(f.ruleId)} ${code(`${f.location.file}:${f.location.line}`)}: ${prose(ui.reason)}: ${isolateAuto(reason, locale)}`,
        );
      }
      out.push('');
    }

    const diags = result.diagnostics.filter((d) => d.level !== 'info');
    if (diags.length > 0) {
      out.push(`## ${prose(ui.diagnosticsTitle)}`, '');
      for (const d of diags) {
        const where = d.file ? `${code(`${d.file}${d.line ? `:${d.line}` : ''}`)} ` : '';
        out.push(`- **${prose(ui.level[d.level])}** ${where}${renderDiagnostic(d, locale, code)}`);
      }
      out.push('');
    }

    if (rtl) out.push('</div>', '');
    return out.join('\n');

    function renderFinding(f: Finding, n: number): string[] {
      const m = meta.get(f.ruleId);
      const title = m ? m.docs.title[locale] : f.ruleId;
      const cwe =
        f.cwe.length > 0
          ? ` · **${prose(ui.cwe)}:** ${f.cwe.map((c) => code(`CWE-${c}`)).join(', ')}`
          : '';
      const lines = [
        `### ${prose(`${n}.`)} ${prose(ui.severity[f.severity])}: ${prose(title)}`,
        '',
        `- **${prose(ui.rule)}:** ${code(f.ruleId)}${cwe}`,
        `- **${prose(ui.location)}:** ${code(`${f.location.file}:${f.location.line}:${f.location.column}`)}`,
        `- **${prose(ui.confidenceLabel)}:** ${prose(ui.confidence[f.confidence])}${f.confidence === 'low' ? ` (${prose(ui.lowConfidenceTag)})` : ''}`,
      ];
      if (f.evidence.length > 0) lines.push(`- **${prose(ui.evidence)}:** ${code(f.evidence)}`);
      lines.push('', renderMessage(f, m, locale, code), '');
      return lines;
    }
  },
};
