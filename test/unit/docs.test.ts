import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { format, resolveConfig } from 'prettier';
import { describe, expect, it } from 'vitest';
import { resolveSettings } from '../../src/core/config/settings.ts';
import { scan } from '../../src/core/engine/engine.ts';
import { DOCS_BASE_URL, ruleDocsUrl, type ReportOptions } from '../../src/reporters/reporter.ts';
import { REPORTERS } from '../../src/reporters/index.ts';
import { ALL_RULES } from '../../src/rules/index.ts';
import {
  extractHandRegions,
  HAND_REGIONS,
  isPlaceholder,
  renderRulePage,
  rulePagePath,
} from '../../scripts/lib/rule-docs.ts';
import { makeProject } from '../helpers/project.ts';

const REPO = fileURLToPath(new URL('../../', import.meta.url));
const BLOB_MAIN = 'https://github.com/italamrii/vibeguard/blob/main/';

/** Map a docs URL on the main branch to a path in this checkout. */
function localPathOf(url: string): string {
  expect(url.startsWith(BLOB_MAIN), url).toBe(true);
  return path.join(REPO, url.slice(BLOB_MAIN.length).split('#')[0] ?? '');
}

describe('rule documentation', () => {
  it('DOCS_BASE_URL points at docs/rules on main', () => {
    expect(DOCS_BASE_URL).toBe(`${BLOB_MAIN}docs/rules`);
  });

  it.each(ALL_RULES.map((r) => [r.meta.id, r] as const))(
    '%s has an up-to-date page with written hand sections',
    async (id, rule) => {
      const file = path.join(REPO, rulePagePath(id));
      expect(existsSync(file), `${rulePagePath(id)} is missing: run npm run docs:rules`).toBe(true);
      const page = readFileSync(file, 'utf8');
      const hand = extractHandRegions(page);
      for (const r of HAND_REGIONS) expect(isPlaceholder(hand[r]), `${id}: ${r}`).toBe(false);
      const expected = await format(renderRulePage(rule.meta, hand), {
        ...(await resolveConfig(file)),
        parser: 'markdown',
        filepath: file,
      });
      expect(page, `${rulePagePath(id)} is stale: run npm run docs:rules`).toBe(expected);
      for (const heading of [
        '## What it detects',
        '## Why it matters',
        '### Vulnerable',
        '### Fixed',
        '## False positives and limitations',
        '## How to suppress',
        '## CWE',
      ])
        expect(page).toContain(heading);
      for (const c of rule.meta.cwe) expect(page).toContain(`CWE-${c}`);
    },
  );

  it('every rule docs URL resolves to a file in the repository', () => {
    for (const r of ALL_RULES) expect(existsSync(localPathOf(ruleDocsUrl(r.meta.id)))).toBe(true);
  });

  it('every docs URL in every report format and language resolves to a file', async () => {
    const root = await makeProject({
      'supabase/migrations/1.sql': 'create table public.notes (id int);',
      'app/api/notes/route.ts': [
        "import { createClient } from '@supabase/supabase-js';",
        'const db = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);',
        'export async function POST() { await db.from("notes").delete().neq("id", 0); }',
      ].join('\n'),
    });
    const result = await scan({ root, settings: resolveSettings(undefined), rules: ALL_RULES });
    expect(result.findings.length).toBeGreaterThan(1);
    const urls = new Set<string>();
    for (const reporter of REPORTERS.values())
      for (const locale of ['en', 'ar'] as const) {
        const opts: ReportOptions = {
          locale,
          color: false,
          toolVersion: '0.0.0',
          failOn: 'high',
          minConfidence: 'low',
        };
        const out = reporter.render(result, opts);
        for (const m of out.matchAll(
          /https:\/\/github\.com\/italamrii\/vibeguard\/[^\s"'<>)\]`]+/g,
        ))
          urls.add(m[0]);
      }
    expect(urls.size).toBeGreaterThanOrEqual(ALL_RULES.length); // SARIF describes every rule
    for (const u of urls) expect(existsSync(localPathOf(u)), u).toBe(true);
  });
});

describe('Markdown links in the repository', () => {
  const SKIP = new Set(['node_modules', '.git', 'dist', 'coverage', 'fixtures', '.fixtures-out']);
  const files: string[] = [];
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir)) {
      if (SKIP.has(name)) continue;
      const abs = path.join(dir, name);
      if (statSync(abs).isDirectory()) walk(abs);
      else if (name.endsWith('.md')) files.push(abs);
    }
  };
  walk(REPO);

  it.each(files.map((f) => [path.relative(REPO, f), f] as const))(
    '%s has no broken relative links',
    (_rel, file) => {
      const text = readFileSync(file, 'utf8').replace(/^(`{3,}|~{3,})[\s\S]*?^\1/gm, '');
      const broken: string[] = [];
      for (const m of text.matchAll(/\]\(([^)\s]+)\)/g)) {
        const target = m[1] ?? '';
        if (/^(?:[a-z]+:|#)/i.test(target)) {
          if (target.startsWith(BLOB_MAIN) && !existsSync(localPathOf(target))) broken.push(target);
          continue;
        }
        const resolved = path.resolve(path.dirname(file), target.split('#')[0] ?? '');
        if (!existsSync(resolved)) broken.push(target);
      }
      expect(broken).toEqual([]);
    },
  );
});
