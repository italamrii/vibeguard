import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { resolveSettings } from '../../src/core/config/settings.ts';
import { scan, type ScanResult } from '../../src/core/engine/engine.ts';
import { LOCALES } from '../../src/i18n/locale.ts';
import { REPORTERS } from '../../src/reporters/index.ts';
import { ALL_RULES } from '../../src/rules/index.ts';
import { compare, readExpectations } from '../helpers/accuracy.ts';
import { buildFixtures, type BuiltFixtures } from '../helpers/fixtures.ts';
import { sarifSchemaErrors } from '../helpers/sarif-validator.ts';
import { checkGitHubSarif } from '../../src/reporters/sarif-github.ts';
import { sarifReporter } from '../../src/reporters/sarif.ts';
import { markdownReporter } from '../../src/reporters/markdown.ts';
import { findUnisolatedLtr } from '../../src/i18n/bidi.ts';

let outDir: string;
let built: BuiltFixtures;
const results = new Map<string, ScanResult>();

beforeAll(async () => {
  outDir = await mkdtemp(path.join(tmpdir(), 'vg-fixtures-'));
  built = await buildFixtures(outDir);
  for (const app of built.apps) {
    results.set(
      app,
      await scan({
        root: path.join(outDir, app),
        settings: resolveSettings(undefined),
        rules: ALL_RULES,
      }),
    );
  }
}, 120_000);

afterAll(async () => {
  await rm(outDir, { recursive: true, force: true });
});

const result = (app: string): ScanResult => {
  const r = results.get(app);
  if (!r) throw new Error(`no result for ${app}`);
  return r;
};

describe('fixture apps', () => {
  it('builds every app pair', () => {
    expect(built.apps.filter((a) => a.endsWith('-clean')).length).toBeGreaterThanOrEqual(3);
    for (const app of built.apps.filter((a) => a.endsWith('-vuln'))) {
      expect(built.apps).toContain(app.replace(/-vuln$/, '-clean'));
    }
  });

  it.each(['next-supabase-clean', 'express-api-clean', 'vite-firebase-clean'])(
    '%s produces zero findings and a complete scan',
    (app) => {
      const r = result(app);
      expect(r.complete).toBe(true);
      const active = r.findings.filter((f) => !f.suppression);
      expect(active.map((f) => `${f.ruleId} ${f.location.file}:${f.location.line}`)).toEqual([]);
      expect(r.diagnostics.filter((d) => d.level !== 'info')).toEqual([]);
    },
  );

  it('documents the one intentional exception in the clean apps with a reasoned suppression', () => {
    const suppressed = built.apps
      .filter((a) => a.endsWith('-clean'))
      .flatMap((a) => result(a).findings.filter((f) => f.suppression));
    expect(
      suppressed.map((f) => [f.ruleId, f.severity, f.confidence, f.suppression?.reason]),
    ).toEqual([
      [
        'supabase/permissive-policy',
        'low',
        'low',
        'countries is public reference data, read-only by design',
      ],
    ]);
  });

  it('surfaces coverage gaps instead of hiding them', () => {
    const codes = (app: string) => result(app).diagnostics.map((d) => d.code);
    expect(codes('next-supabase-vuln')).toContain('parse-failed');
    expect(codes('next-supabase-vuln')).toContain('dynamic-sql');
    expect(codes('vite-firebase-vuln')).toContain('no-migrations');
  });

  it.each(['next-supabase-vuln', 'express-api-vuln', 'vite-firebase-vuln'])(
    '%s matches its annotations exactly (no false positives, no unexpected misses)',
    async (app) => {
      const r = result(app);
      expect(r.complete).toBe(true);
      const c = compare(await readExpectations(path.join(outDir, app)), r.findings);
      expect(
        c.falsePositives.map((f) => `${f.ruleId} ${f.location.file}:${f.location.line}`),
      ).toEqual([]);
      expect(c.falseNegatives.map((e) => `${e.ruleId} ${e.file}:${e.line}`)).toEqual([]);
      expect(r.findings.length).toBeGreaterThan(10);
    },
  );
});

describe('redaction canary', () => {
  /**
   * Render every reporter in every locale for every vulnerable app, and check that no
   * 12-character window of any fake secret appears. That catches the full secret, and
   * any partial leak beyond the 4-character prefix the redaction format allows.
   */
  it('never prints any part of a secret beyond the redacted prefix, in any format or language', () => {
    expect(built.secrets.length).toBeGreaterThan(20);
    const windows = new Set<string>();
    for (const s of built.secrets) {
      // PEM armour lines are public boilerplate; only the base64 body is secret.
      const body = s.includes('PRIVATE KEY')
        ? s.replace(/-----[A-Z ]+-----/g, '').replace(/\\n|\s/g, '')
        : s;
      for (let i = 0; i + 12 <= body.length; i++) windows.add(body.slice(i, i + 12));
    }
    let rendered = 0;
    for (const app of built.apps.filter((a) => a.endsWith('-vuln'))) {
      for (const reporter of REPORTERS.values()) {
        for (const locale of LOCALES) {
          const out = reporter.render(result(app), {
            locale,
            color: false,
            toolVersion: 'test',
            failOn: 'high',
            minConfidence: 'low',
          });
          rendered++;
          const leaked = [...windows].filter((w) => out.includes(w));
          expect(leaked, `${app} ${reporter.format} ${locale}`).toEqual([]);
        }
      }
    }
    expect(rendered).toBe(3 * REPORTERS.size * LOCALES.length);
  });
});

describe('report formats on every fixture app', () => {
  const opts = (locale: 'en' | 'ar') => ({
    locale,
    color: false,
    toolVersion: '0.1.0',
    failOn: 'high' as const,
    minConfidence: 'low' as const,
  });

  it('SARIF validates against the official schema and GitHub constraints, in both languages', () => {
    for (const app of built.apps) {
      for (const locale of ['en', 'ar'] as const) {
        const out = sarifReporter.render(result(app), opts(locale));
        expect(sarifSchemaErrors(out), `${app} ${locale}`).toEqual([]);
        expect(checkGitHubSarif(out), `${app} ${locale}`).toEqual([]);
      }
    }
  });

  it('Arabic Markdown has no unisolated LTR run on any Arabic line', () => {
    for (const app of built.apps) {
      expect(findUnisolatedLtr(markdownReporter.render(result(app), opts('ar'))), app).toEqual([]);
    }
  });
});
