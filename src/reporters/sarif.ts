import type { ScanResult } from '../core/engine/engine.ts';
import type { RuleMeta } from '../core/engine/rule.ts';
import type { Diagnostic, Finding } from '../core/findings/finding.ts';
import type { Severity } from '../core/findings/severity.ts';
import { isolateLtr, isolateLtrRuns } from '../i18n/bidi.ts';
import { interpolate, isRtl, type Locale } from '../i18n/locale.ts';
import { UI } from '../i18n/ui.ts';
import { ruleHelpMarkdown } from './markdown.ts';
import {
  isPartialCoverage,
  renderDiagnostic,
  renderMessage,
  ruleDocsUrl,
  ruleIndex,
  type Reporter,
  type ReportOptions,
} from './reporter.ts';
import { sanitizeUntrusted } from './text-safety.ts';

/**
 * SARIF 2.1.0 output for GitHub code scanning and other SARIF consumers (ADR-0014).
 *
 * - Every rule that ran is described in `tool.driver.rules` with help text (plain and
 *   Markdown), `helpUri`, CWE tags and `security-severity` (GitHub maps it to
 *   critical / high / medium / low).
 * - Results carry `partialFingerprints["vibeguard/v1"]`, the engine's line-independent
 *   fingerprint, so alerts do not churn when unrelated lines move.
 * - Inline suppressions become `suppressions: [{ kind: "inSource", justification }]`.
 * - Scan diagnostics, partial coverage and incomplete scans become invocation
 *   notifications; `executionSuccessful` is false for an incomplete scan.
 * - Evidence is the redacted string from the engine (region.snippet); nothing else from the
 *   scanned file is copied.
 */

export const SARIF_SCHEMA_URL = 'https://json.schemastore.org/sarif-2.1.0.json';
export const FINGERPRINT_KEY = 'vibeguard/v1';
/** GitHub code scanning rejects runs with more results than this. */
export const MAX_RESULTS_PER_RUN = 25_000;

/** GitHub: >= 9.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low. */
export const SECURITY_SEVERITY: Readonly<Record<Severity, string>> = {
  critical: '9.5',
  high: '8.0',
  medium: '5.5',
  low: '2.5',
};

const LEVEL: Readonly<Record<Severity, 'error' | 'warning' | 'note'>> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
};

/** `secrets/provider-key` → `SecretsProviderKey` (SARIF reportingDescriptor.name). */
function ruleName(id: string): string {
  return id
    .split(/[/-]/)
    .map((p) => (p[0]?.toUpperCase() ?? '') + p.slice(1))
    .join('');
}

/** Relative, percent-encoded URI (GitHub requires URIs relative to the checkout). */
export function artifactUri(relPath: string): string {
  return relPath.split('/').map(encodeURIComponent).join('/');
}

function plain(s: string, locale: Locale): string {
  return isRtl(locale) ? isolateLtrRuns(s) : s;
}

function ruleDescriptor(m: RuleMeta, locale: Locale): Record<string, unknown> {
  const r = m.docs.remediation;
  const ui = UI[locale];
  const helpText = [
    m.docs.summary[locale],
    '',
    r.text[locale],
    '',
    `${ui.vulnerable}:`,
    r.vulnerable,
    '',
    `${ui.fixed}:`,
    r.fixed,
  ].join('\n');
  return {
    id: m.id,
    name: ruleName(m.id),
    shortDescription: { text: plain(m.docs.title[locale], locale) },
    fullDescription: { text: plain(m.docs.summary[locale], locale) },
    help: {
      text: plain(helpText, locale),
      markdown: ruleHelpMarkdown(m, locale, 2).join('\n'),
    },
    helpUri: ruleDocsUrl(m.id),
    defaultConfiguration: { level: LEVEL[m.defaultSeverity] },
    properties: {
      tags: ['security', m.family, ...m.cwe.map((c) => `external/cwe/cwe-${c}`)].slice(0, 20),
      'security-severity': SECURITY_SEVERITY[m.defaultSeverity],
      'problem.severity':
        LEVEL[m.defaultSeverity] === 'note' ? 'recommendation' : LEVEL[m.defaultSeverity],
    },
  };
}

function resultOf(
  f: Finding,
  meta: RuleMeta | undefined,
  ruleIdx: number,
  locale: Locale,
): Record<string, unknown> {
  const region: Record<string, unknown> = {
    startLine: f.location.line,
    startColumn: f.location.column,
  };
  if (f.location.endLine !== undefined) region['endLine'] = f.location.endLine;
  if (
    f.location.endColumn !== undefined &&
    (f.location.endLine ?? f.location.line) >= f.location.line
  ) {
    region['endColumn'] = f.location.endColumn;
  }
  if (f.evidence.length > 0) region['snippet'] = { text: sanitizeUntrusted(f.evidence) };
  const wrap = (v: string): string => isolateLtr(v, locale);
  const result: Record<string, unknown> = {
    ruleId: f.ruleId,
    ruleIndex: ruleIdx,
    level: LEVEL[f.severity],
    message: { text: renderMessage(f, meta, locale, wrap) },
    locations: [
      {
        physicalLocation: {
          artifactLocation: { uri: artifactUri(f.location.file), uriBaseId: '%SRCROOT%' },
          region,
        },
      },
    ],
    partialFingerprints: { [FINGERPRINT_KEY]: f.fingerprint },
    properties: {
      severity: f.severity,
      confidence: f.confidence,
      'security-severity': SECURITY_SEVERITY[f.severity],
      cwe: f.cwe.map((c) => `CWE-${c}`),
    },
  };
  if (f.suppression) {
    result['suppressions'] = [
      {
        kind: 'inSource',
        status: 'accepted',
        justification: sanitizeUntrusted(f.suppression.reason),
      },
    ];
  }
  return result;
}

function notification(
  id: string,
  level: 'error' | 'warning' | 'note',
  text: string,
  file?: string,
  line?: number,
): Record<string, unknown> {
  const n: Record<string, unknown> = { descriptor: { id }, level, message: { text } };
  if (file !== undefined) {
    n['locations'] = [
      {
        physicalLocation: {
          artifactLocation: { uri: artifactUri(file), uriBaseId: '%SRCROOT%' },
          ...(line !== undefined ? { region: { startLine: line } } : {}),
        },
      },
    ];
  }
  return n;
}

function diagnosticNotification(d: Diagnostic, locale: Locale): Record<string, unknown> {
  const level = d.level === 'error' ? 'error' : d.level === 'warning' ? 'warning' : 'note';
  const text = renderDiagnostic(d, locale, (v) => isolateLtr(v, locale));
  return notification(d.code, level, text, d.file, d.line);
}

export const sarifReporter: Reporter = {
  format: 'sarif',
  render(result: ScanResult, opts: ReportOptions): string {
    const { locale } = opts;
    const ui = UI[locale];
    const metas = ruleIndex(result);
    const ruleOrder = new Map(result.rules.map((r, i) => [r.id, i]));

    // Findings arrive sorted most severe first, so truncation keeps the worst ones.
    const findings = result.findings.slice(0, MAX_RESULTS_PER_RUN);
    const notifications: Record<string, unknown>[] = result.diagnostics.map((d) =>
      diagnosticNotification(d, locale),
    );
    if (!result.complete)
      notifications.push(notification('scan-incomplete', 'error', plain(ui.incomplete, locale)));
    if (isPartialCoverage(result))
      notifications.push(
        notification('partial-coverage', 'warning', plain(ui.partialCoverage, locale)),
      );
    if (result.findings.length > findings.length) {
      notifications.push(
        notification(
          'results-truncated',
          'warning',
          plain(
            interpolate(ui.sarifTruncated, {
              kept: findings.length,
              total: result.findings.length,
            }),
            locale,
          ),
        ),
      );
    }

    const doc = {
      $schema: SARIF_SCHEMA_URL,
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'VibeGuard',
              semanticVersion: opts.toolVersion,
              version: opts.toolVersion,
              informationUri: 'https://github.com/italamrii/vibeguard',
              language: locale,
              rules: result.rules.map((m) => ruleDescriptor(m, locale)),
            },
          },
          invocations: [
            {
              executionSuccessful: result.complete,
              toolExecutionNotifications: notifications,
            },
          ],
          // Paths are relative to the scan root; the absolute root is never written (privacy).
          columnKind: 'utf16CodeUnits',
          language: locale,
          results: findings.map((f) =>
            resultOf(f, metas.get(f.ruleId), ruleOrder.get(f.ruleId) ?? 0, locale),
          ),
          properties: {
            complete: result.complete,
            partialCoverage: isPartialCoverage(result),
            filesScanned: result.filesScanned,
            belowConfidenceThreshold: result.belowConfidenceThreshold,
            failOn: opts.failOn,
            minConfidence: opts.minConfidence,
            notice: ui.ownCodeNotice,
          },
        },
      ],
    };
    return `${JSON.stringify(doc, null, 2)}\n`;
  },
};
