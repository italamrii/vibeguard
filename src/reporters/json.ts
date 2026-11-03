import type { ScanResult } from '../core/engine/engine.ts';
import { UI } from '../i18n/ui.ts';
import {
  countFindings,
  isPartialCoverage,
  renderDiagnostic,
  renderMessage,
  ruleDocsUrl,
  ruleIndex,
  type Reporter,
  type ReportOptions,
} from './reporter.ts';

export const JSON_SCHEMA_VERSION = 1;
export const JSON_SCHEMA_URL =
  'https://raw.githubusercontent.com/italamrii/vibeguard/main/schema/findings.v1.schema.json';

/**
 * Machine-readable output. Contract: schema/findings.v1.schema.json. Includes suppressed
 * findings (with their justification) so audits can see what was waived. Human text
 * (`title`, `message`) is rendered in the selected locale; `messageId` and `params` are
 * stable for programmatic use.
 */
export const jsonReporter: Reporter = {
  format: 'json',
  render(result: ScanResult, opts: ReportOptions): string {
    const meta = ruleIndex(result);
    const counts = countFindings(result.findings);
    const doc = {
      $schema: JSON_SCHEMA_URL,
      schemaVersion: JSON_SCHEMA_VERSION,
      tool: { name: 'vibeguard', version: opts.toolVersion },
      locale: opts.locale,
      complete: result.complete,
      partialCoverage: isPartialCoverage(result),
      summary: {
        filesScanned: result.filesScanned,
        durationMs: result.durationMs,
        findings: counts.bySeverity,
        total: counts.active,
        suppressed: counts.suppressed,
        belowConfidenceThreshold: result.belowConfidenceThreshold,
        failOn: opts.failOn,
        minConfidence: opts.minConfidence,
      },
      findings: result.findings.map((f) => {
        const m = meta.get(f.ruleId);
        return {
          ruleId: f.ruleId,
          title: m?.docs.title[opts.locale] ?? f.ruleId,
          severity: f.severity,
          confidence: f.confidence,
          location: f.location,
          message: renderMessage(f, m, opts.locale),
          messageId: f.messageId,
          params: f.params,
          evidence: f.evidence,
          cwe: f.cwe.map((n) => `CWE-${n}`),
          references: f.references,
          docsUrl: ruleDocsUrl(f.ruleId),
          fingerprint: f.fingerprint,
          ...(f.suppression ? { suppression: f.suppression } : {}),
        };
      }),
      diagnostics: result.diagnostics.map((d) => ({
        level: d.level,
        code: d.code,
        message: renderDiagnostic(d, opts.locale),
        ...(d.file !== undefined ? { file: d.file } : {}),
        ...(d.line !== undefined ? { line: d.line } : {}),
      })),
      notice: UI[opts.locale].ownCodeNotice,
    };
    return `${JSON.stringify(doc, null, 2)}\n`;
  },
};
