import { describe, expect, it } from 'vitest';
import { resolveSettings } from '../../../src/core/config/settings.ts';
import { scan, type ScanResult } from '../../../src/core/engine/engine.ts';
import type { Finding } from '../../../src/core/findings/finding.ts';
import { redactSecret } from '../../../src/core/redaction/redact.ts';
import type { Locale } from '../../../src/i18n/locale.ts';
import type { ReportOptions } from '../../../src/reporters/reporter.ts';
import { checkGitHubSarif } from '../../../src/reporters/sarif-github.ts';
import {
  artifactUri,
  FINGERPRINT_KEY,
  MAX_RESULTS_PER_RUN,
  sarifReporter,
} from '../../../src/reporters/sarif.ts';
import { ALL_RULES } from '../../../src/rules/index.ts';
import { makeProject } from '../../helpers/project.ts';
import { sarifSchemaErrors } from '../../helpers/sarif-validator.ts';
import { crashingRule, markerRule } from '../../helpers/test-rules.ts';

const opts = (locale: Locale = 'en'): ReportOptions => ({
  locale,
  color: false,
  toolVersion: '0.1.0',
  failOn: 'high',
  minConfidence: 'low',
});

interface SarifDoc {
  runs: {
    tool: {
      driver: {
        rules: {
          id: string;
          helpUri: string;
          help: { text: string; markdown: string };
          properties: { tags: string[]; 'security-severity': string };
        }[];
      };
    };
    invocations: {
      executionSuccessful: boolean;
      toolExecutionNotifications: {
        descriptor: { id: string };
        level: string;
        message: { text: string };
      }[];
    }[];
    results: {
      ruleId: string;
      ruleIndex: number;
      level: string;
      message: { text: string };
      locations: {
        physicalLocation: {
          artifactLocation: { uri: string };
          region: { startLine: number; snippet?: { text: string } };
        };
      }[];
      partialFingerprints: Record<string, string>;
      suppressions?: { kind: string; justification: string }[];
    }[];
  }[];
}

const parse = (s: string): SarifDoc => JSON.parse(s) as SarifDoc;

async function richResult(): Promise<ScanResult> {
  const root = await makeProject({
    'supabase/migrations/1.sql':
      'create table public.notes (id int);\nalter table public.x enable row level securty;',
    'src/my file.ts': [
      "const stripe = new Stripe('" +
        ['sk', 'live', '51', 'Qx7Lm2Np9Rt4Vw8Yz3Bc6Df1Gh5Jk0Mn'].join('_').replace('_51_', '_51') +
        "');",
      '// vibeguard-ignore-next-line secrets/high-entropy -- sample value from the vendor docs',
      "const apiSecret = 'k3Pq9xZ2mN7vB4wR8tY1uL6';",
    ].join('\n'),
  });
  return scan({ root, settings: resolveSettings(undefined), rules: ALL_RULES });
}

describe('sarif reporter', () => {
  it.each(['en', 'ar'] as const)(
    'validates against the official SARIF 2.1.0 schema and GitHub constraints (%s)',
    async (locale) => {
      const out = sarifReporter.render(await richResult(), opts(locale));
      expect(sarifSchemaErrors(out)).toEqual([]);
      expect(checkGitHubSarif(out)).toEqual([]);
    },
  );

  it('describes every rule that ran, with help, helpUri, CWE tags and security-severity', async () => {
    const doc = parse(sarifReporter.render(await richResult(), opts()));
    const rules = doc.runs[0]?.tool.driver.rules ?? [];
    expect(rules.map((r) => r.id)).toEqual(ALL_RULES.map((r) => r.meta.id));
    for (const r of rules) {
      expect(r.helpUri).toMatch(/^https:\/\/github\.com\/.+\/docs\/rules\/.+\.md$/);
      expect(r.help.text.length).toBeGreaterThan(50);
      expect(r.help.markdown).toContain('```');
      expect(r.properties.tags).toContain('security');
      expect(r.properties.tags.some((t) => t.startsWith('external/cwe/cwe-'))).toBe(true);
    }
    const sev = (id: string) => rules.find((r) => r.id === id)?.properties['security-severity'];
    expect(sev('secrets/provider-key')).toBe('9.5'); // critical
    expect(sev('secrets/provider-key-test')).toBe('2.5'); // low: split so GitHub ranks it correctly
    expect(sev('secrets/high-entropy')).toBe('8.0'); // high
    expect(sev('endpoints/auth-route-no-rate-limit')).toBe('5.5'); // medium
    expect(sev('supabase/rls-no-policies')).toBe('2.5'); // low
  });

  it('maps results: ruleIndex, level, relative encoded URI, redacted snippet, fingerprint', async () => {
    const r = await richResult();
    const doc = parse(sarifReporter.render(r, opts()));
    const res = doc.runs[0]?.results.find((x) => x.ruleId === 'secrets/provider-key');
    expect(res).toBeDefined();
    expect(doc.runs[0]?.tool.driver.rules[res?.ruleIndex ?? -1]?.id).toBe('secrets/provider-key');
    expect(res?.level).toBe('error');
    const loc = res?.locations[0]?.physicalLocation;
    expect(loc?.artifactLocation.uri).toBe('src/my%20file.ts');
    expect(loc?.region.snippet?.text).toMatch(/^sk_l…\[\d+ chars\]$/);
    expect(res?.partialFingerprints[FINGERPRINT_KEY]).toMatch(/^[0-9a-f]{32}$/);
    expect(JSON.stringify(doc)).not.toContain(r.root); // no absolute paths
  });

  it('keeps fingerprints stable when unrelated lines move', async () => {
    const files = (pad: string) => ({
      'a.ts': `${pad}const stripe = new Stripe('${['sk', 'live', '51Qx7Lm2Np9Rt4Vw8Yz3Bc6Df1Gh5Jk0MnPq'].join('_')}');`,
    });
    const fp = async (pad: string) => {
      const root = await makeProject(files(pad));
      const out = parse(
        sarifReporter.render(
          await scan({ root, settings: resolveSettings(undefined), rules: ALL_RULES }),
          opts(),
        ),
      );
      return out.runs[0]?.results.map((x) => x.partialFingerprints[FINGERPRINT_KEY]);
    };
    expect(await fp('')).toEqual(await fp('\n\n// moved\n\n'));
  });

  it('maps inline suppressions to inSource suppressions with the reason', async () => {
    const doc = parse(sarifReporter.render(await richResult(), opts()));
    const s = doc.runs[0]?.results.find((x) => x.suppressions);
    expect(s?.ruleId).toBe('secrets/high-entropy');
    expect(s?.suppressions).toEqual([
      { kind: 'inSource', status: 'accepted', justification: 'sample value from the vendor docs' },
    ]);
  });

  it('surfaces partial coverage and diagnostics as invocation notifications', async () => {
    const inv = parse(sarifReporter.render(await richResult(), opts())).runs[0]?.invocations[0];
    expect(inv?.executionSuccessful).toBe(true);
    const ids = inv?.toolExecutionNotifications.map((n) => `${n.descriptor.id}:${n.level}`);
    expect(ids).toContain('parse-failed:warning');
    expect(ids).toContain('partial-coverage:warning');
  });

  it('marks an incomplete scan as unsuccessful, with a notification', async () => {
    const root = await makeProject({ 'a.ts': 'VG_TEST_MARKER' });
    const r = await scan({
      root,
      settings: resolveSettings(undefined),
      rules: [markerRule, crashingRule],
    });
    const out = sarifReporter.render(r, opts());
    expect(sarifSchemaErrors(out)).toEqual([]);
    const inv = parse(out).runs[0]?.invocations[0];
    expect(inv?.executionSuccessful).toBe(false);
    expect(inv?.toolExecutionNotifications.map((n) => n.descriptor.id)).toEqual([
      'rule-crashed',
      'scan-incomplete',
    ]);
    expect(out).not.toContain('51HxQabcdefghijklmnopqrstuv'); // crash message is scrubbed
  });

  it('truncates to GitHub’s per-run result limit, keeping the most severe, and says so', async () => {
    const base = await richResult();
    const f0 = base.findings[0] as Finding;
    const many: Finding[] = Array.from({ length: MAX_RESULTS_PER_RUN + 5 }, (_, i) => ({
      ...f0,
      evidence: redactSecret(`value-${i}-xxxxxxxxxxxxxxxx`),
      fingerprint: i.toString(16).padStart(32, '0'),
    }));
    const out = sarifReporter.render({ ...base, findings: many }, opts());
    const doc = parse(out);
    expect(doc.runs[0]?.results).toHaveLength(MAX_RESULTS_PER_RUN);
    expect(
      doc.runs[0]?.invocations[0]?.toolExecutionNotifications.map((n) => n.descriptor.id),
    ).toContain('results-truncated');
    expect(checkGitHubSarif(out)).toEqual([]);
  });

  it('percent-encodes path segments but keeps separators', () => {
    expect(artifactUri('src/a b/c#d.ts')).toBe('src/a%20b/c%23d.ts');
  });
});

describe('checkGitHubSarif', () => {
  it('reports constraint violations', () => {
    const bad = JSON.stringify({
      version: '2.1.0',
      runs: [
        {
          tool: {
            driver: {
              name: 'x',
              rules: [
                {
                  id: 'r',
                  helpUri: 'u',
                  help: { text: 't' },
                  properties: { 'security-severity': 'high' },
                },
              ],
            },
          },
          results: [
            {
              ruleId: 'r',
              level: 'error',
              message: { text: 'm' },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: '/abs/path.ts' },
                    region: { startLine: 0 },
                  },
                },
              ],
            },
          ],
        },
      ],
    });
    const problems = checkGitHubSarif(bad);
    expect(problems.join('\n')).toMatch(/security-severity/);
    expect(problems.join('\n')).toMatch(/partialFingerprints/);
    expect(problems.join('\n')).toMatch(/relative/);
    expect(problems.join('\n')).toMatch(/startLine/);
  });
});

describe('sarifSchemaErrors (the validator itself)', () => {
  it('rejects documents that violate the official schema', () => {
    const bad = {
      version: '2.1.0',
      runs: [
        { tool: { driver: { name: 'x' } }, results: [{ message: { text: 'm' }, level: 'fatal' }] },
      ],
    };
    expect(sarifSchemaErrors(JSON.stringify(bad)).length).toBeGreaterThan(0);
    expect(
      sarifSchemaErrors(JSON.stringify({ version: '2.0.0', runs: [] })).length,
    ).toBeGreaterThan(0);
  });
});
