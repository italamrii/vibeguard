import { readFileSync } from 'node:fs';
import { Ajv2020 } from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';
import { resolveSettings } from '../../../src/core/config/settings.ts';
import { scan, type ScanResult } from '../../../src/core/engine/engine.ts';
import { LRI, PDI } from '../../../src/i18n/bidi.ts';
import type { Locale } from '../../../src/i18n/locale.ts';
import { jsonReporter } from '../../../src/reporters/json.ts';
import { markdownReporter, mdCode } from '../../../src/reporters/markdown.ts';
import type { ReportOptions } from '../../../src/reporters/reporter.ts';
import { terminalReporter } from '../../../src/reporters/terminal.ts';
import { sanitizeUntrusted } from '../../../src/reporters/text-safety.ts';
import { makeProject } from '../../helpers/project.ts';
import { markerRule } from '../../helpers/test-rules.ts';

const opts = (locale: Locale = 'en'): ReportOptions => ({
  locale,
  color: false,
  toolVersion: '0.0.0-test',
  failOn: 'high',
  minConfidence: 'low',
});

/** Durations vary between runs; pin them so output is comparable. */
const stable = (r: ScanResult): ScanResult => ({ ...r, durationMs: 1 });

async function sampleResult(): Promise<ScanResult> {
  const root = await makeProject({
    'src/app.ts':
      'VG_TEST_MARKER\n// vibeguard-ignore-next-line test/marker -- accepted for the demo app\nVG_TEST_MARKER:low',
    'src/lib.ts': 'VG_TEST_MARKER:low:medium',
  });
  return stable(await scan({ root, settings: resolveSettings(undefined), rules: [markerRule] }));
}

describe('json reporter', () => {
  it('validates against the published schema', async () => {
    const schema = JSON.parse(
      readFileSync(new URL('../../../schema/findings.v1.schema.json', import.meta.url), 'utf8'),
    ) as object;
    const validate = new Ajv2020({ strict: true, allErrors: true }).compile(schema);
    for (const locale of ['en', 'ar'] as const) {
      const doc: unknown = JSON.parse(jsonReporter.render(await sampleResult(), opts(locale)));
      expect(validate(doc), JSON.stringify(validate.errors)).toBe(true);
    }
  });

  it('includes suppressed findings with their reason and never the absolute root', async () => {
    const r = await sampleResult();
    const out = jsonReporter.render(r, opts());
    expect(out).not.toContain(r.root);
    const doc = JSON.parse(out) as {
      summary: { total: number; suppressed: number };
      findings: { suppression?: unknown }[];
    };
    expect(doc.summary).toMatchObject({ total: 2, suppressed: 1 });
    expect(doc.findings.filter((f) => f.suppression)).toHaveLength(1);
  });
});

describe('terminal reporter', () => {
  it('renders findings, the remediation section and the summary', async () => {
    const out = terminalReporter.render(await sampleResult(), opts());
    expect(out).toMatchSnapshot();
    expect(out).not.toContain('\u001b['); // no colour when color=false
  });

  it('labels low-confidence findings instead of hiding them', async () => {
    const out = terminalReporter.render(await sampleResult(), opts());
    expect(out).toContain('low confidence: verify manually');
  });
});

describe('markdown reporter', () => {
  it('renders English', async () => {
    expect(markdownReporter.render(await sampleResult(), opts('en'))).toMatchSnapshot();
  });

  it('renders Arabic RTL-safe: rtl wrapper, ltr code blocks, isolated inline tokens', async () => {
    const md = markdownReporter.render(await sampleResult(), opts('ar'));
    expect(md.startsWith('<div dir="rtl">')).toBe(true);
    expect(md.trimEnd().endsWith('</div>')).toBe(true);
    expect(md).toContain('<div dir="ltr">\n\n```ts');
    expect(md).toContain(`${LRI}\`test/marker\`${PDI}`);
    expect(md).toContain(`${LRI}\`src/lib.ts:1:1\`${PDI}`);
    expect(md).toMatchSnapshot();
  });
});

describe('untrusted text handling', () => {
  it('neutralises ANSI escapes and bidi overrides', () => {
    expect(sanitizeUntrusted('a\u001b[2Jb')).toBe('a<U+001B>[2Jb');
    expect(sanitizeUntrusted('admin\u202e \u2066// check')).toBe('admin<U+202E> <U+2066>// check');
    expect(sanitizeUntrusted('a\nb')).toBe('a b');
  });

  it('cannot be broken out of a markdown code span', () => {
    expect(mdCode('a`b')).toBe('``a`b``');
    expect(mdCode('`x`')).toBe('`` `x` ``');
  });

  it('sanitises hostile file names in every reporter', async () => {
    const root = await makeProject({ 'evil\u001b[31m.ts': 'VG_TEST_MARKER' });
    const r = stable(
      await scan({ root, settings: resolveSettings(undefined), rules: [markerRule] }),
    );
    for (const rep of [terminalReporter, markdownReporter]) {
      const out = rep.render(r, opts());
      expect(out).not.toContain('\u001b');
      expect(out).toContain('evil<U+001B>[31m.ts');
    }
  });
});
