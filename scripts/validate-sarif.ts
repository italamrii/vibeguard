/**
 * End-to-end SARIF check for CI: run the *built* CLI on every fixture app in every language,
 * then validate each file against the vendored OASIS SARIF 2.1.0 schema and GitHub code
 * scanning's documented constraints. Requires `npm run build` first.
 *
 * A real upload to GitHub code scanning is a pre-release task (docs/release-checklist.md).
 */
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { LOCALES } from '../src/i18n/locale.ts';
import { checkGitHubSarif } from '../src/reporters/sarif-github.ts';
import { buildFixtures, FIXTURES_DIR } from '../test/helpers/fixtures.ts';
import { sarifSchemaErrors } from '../test/helpers/sarif-validator.ts';

const cli = path.join(path.dirname(FIXTURES_DIR), 'dist', 'cli', 'index.js');
const work = await mkdtemp(path.join(tmpdir(), 'vg-sarif-'));
let failures = 0;
try {
  const built = await buildFixtures(path.join(work, 'apps'));
  for (const app of built.apps) {
    for (const lang of LOCALES) {
      const out = path.join(work, `${app}.${lang}.sarif`);
      execFileSync(
        process.execPath,
        [
          cli,
          'scan',
          path.join(built.outDir, app),
          '--format',
          'sarif',
          '--lang',
          lang,
          '--output',
          out,
          '--fail-on',
          'none',
        ],
        { stdio: 'inherit' },
      );
      const text = await readFile(out, 'utf8');
      const problems = [
        ...sarifSchemaErrors(text).map((e) => `schema: ${e}`),
        ...checkGitHubSarif(text).map((e) => `github: ${e}`),
      ];
      const results =
        (JSON.parse(text) as { runs: { results: unknown[] }[] }).runs[0]?.results.length ?? 0;
      console.log(
        `${problems.length === 0 ? 'ok  ' : 'FAIL'} ${app} (${lang}): ${results} results, ${text.length} bytes`,
      );
      for (const p of problems) console.log(`     ${p}`);
      failures += problems.length;
    }
  }
} finally {
  await rm(work, { recursive: true, force: true });
}
if (failures > 0) {
  console.error(`${failures} SARIF problem(s)`);
  process.exitCode = 1;
}
