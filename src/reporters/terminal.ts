import pc from 'picocolors';
import type { ScanResult } from '../core/engine/engine.ts';
import type { Finding } from '../core/findings/finding.ts';
import type { Severity } from '../core/findings/severity.ts';
import { isolateLtr } from '../i18n/bidi.ts';
import { interpolate } from '../i18n/locale.ts';
import { UI } from '../i18n/ui.ts';
import {
  activeFindings,
  countFindings,
  formatLocation,
  renderDiagnostic,
  renderMessage,
  ruleDocsUrl,
  ruleIndex,
  rulesWithFindings,
  type Reporter,
  type ReportOptions,
} from './reporter.ts';
import { sanitizeUntrusted } from './text-safety.ts';

type Paint = (s: string) => string;

type Palette = Record<Severity | 'dim' | 'bold' | 'warn', Paint>;

function palette(color: boolean): Palette {
  const c = pc.createColors(color);
  return {
    critical: (s) => c.bold(c.bgRed(c.white(s))),
    high: (s) => c.bold(c.red(s)),
    medium: (s) => c.yellow(s),
    low: (s) => c.cyan(s),
    dim: c.dim,
    bold: c.bold,
    warn: (s) => c.bold(c.yellow(s)),
  };
}

export const terminalReporter: Reporter = {
  format: 'terminal',
  render(result: ScanResult, opts: ReportOptions): string {
    const { locale } = opts;
    const ui = UI[locale];
    const p = palette(opts.color);
    const ltr = (s: string): string => isolateLtr(s, locale);
    const meta = ruleIndex(result);
    const out: string[] = [];

    out.push(p.bold(ui.reportTitle), p.dim(ui.ownCodeNotice), '');

    if (!result.complete) out.push(p.warn(`! ${ui.incomplete}`), '');

    const findings = groupByFile(activeFindings(result));
    let currentFile: string | undefined;
    for (const f of findings) {
      if (f.location.file !== currentFile) {
        currentFile = f.location.file;
        out.push(p.bold(ltr(sanitizeUntrusted(currentFile))));
      }
      out.push(...renderFinding(f));
    }

    if (findings.length > 0) {
      out.push(p.bold(ui.howToFix));
      for (const m of rulesWithFindings(result)) {
        out.push(`  ${p.bold(ltr(m.id))}  ${m.docs.title[locale]}`);
        out.push(`    ${m.docs.remediation.text[locale]}`);
        out.push(`    ${p.dim(`${ui.docs}: ${ltr(ruleDocsUrl(m.id))}`)}`);
      }
      out.push('');
    }

    const shownDiags = result.diagnostics.filter((d) => d.level !== 'info');
    if (shownDiags.length > 0) {
      out.push(p.bold(ui.diagnosticsTitle));
      for (const d of shownDiags) {
        const where = d.file
          ? `${ltr(sanitizeUntrusted(d.file))}${d.line ? `:${d.line}` : ''}  `
          : '';
        const tag = d.level === 'error' ? p.high('error') : p.medium('warn');
        out.push(`  ${tag}  ${where}${renderDiagnostic(d, locale, ltr)}`);
      }
      out.push('');
    }

    out.push(...renderSummary(result, opts, p));
    return `${out.join('\n')}\n`;

    function renderFinding(f: Finding): string[] {
      const m = meta.get(f.ruleId);
      const sev = p[f.severity](` ${ui.severity[f.severity].toUpperCase()} `);
      const title = m ? m.docs.title[locale] : f.ruleId;
      const lines = [
        `  ${sev} ${title}  ${p.dim(ltr(f.ruleId))}`,
        `    ${p.dim(`${ui.location}:`)} ${ltr(formatLocation(f))}`,
        `    ${renderMessage(f, m, locale, ltr)}`,
      ];
      if (f.evidence.length > 0) {
        lines.push(`    ${p.dim(`${ui.evidence}:`)} ${ltr(sanitizeUntrusted(f.evidence))}`);
      }
      const conf = `${ui.confidenceLabel}: ${ui.confidence[f.confidence]}`;
      lines.push(
        `    ${p.dim(conf)}${f.confidence === 'low' ? `  ${p.warn(`[${ui.lowConfidenceTag}]`)}` : ''}`,
      );
      lines.push('');
      return lines;
    }
  },
};

/**
 * Keep each file's findings together (one header per file), ordering files by their most
 * severe finding so the worst problems are still at the top. Input is already sorted by
 * severity, then location (engine.compareFindings).
 */
function groupByFile(findings: readonly Finding[]): Finding[] {
  const order: string[] = [];
  const byFile = new Map<string, Finding[]>();
  for (const f of findings) {
    let list = byFile.get(f.location.file);
    if (!list) {
      list = [];
      byFile.set(f.location.file, list);
      order.push(f.location.file);
    }
    list.push(f);
  }
  return order.flatMap((file) => byFile.get(file) ?? []);
}

function renderSummary(result: ScanResult, opts: ReportOptions, p: Palette): string[] {
  const ui = UI[opts.locale];
  const counts = countFindings(result.findings);
  const out: string[] = [];
  if (counts.active === 0) {
    out.push(p.bold(ui.noFindings));
  } else {
    const parts = (['critical', 'high', 'medium', 'low'] as const)
      .filter((s) => counts.bySeverity[s] > 0)
      .map((s) => `${counts.bySeverity[s]} ${ui.severity[s]}`);
    out.push(
      `${ui.summary}: ${interpolate(ui.findingsCount, { count: counts.active })} (${parts.join(', ')})`,
    );
  }
  if (counts.suppressed > 0)
    out.push(interpolate(ui.suppressedCount, { count: counts.suppressed }));
  if (result.belowConfidenceThreshold > 0) {
    out.push(
      interpolate(ui.belowThreshold, {
        count: result.belowConfidenceThreshold,
        threshold: ui.confidence[opts.minConfidence],
      }),
    );
  }
  out.push(
    p.dim(interpolate(ui.filesScanned, { count: result.filesScanned, ms: result.durationMs })),
  );
  return out;
}
