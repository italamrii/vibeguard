/**
 * Materialise the fixture apps (templates in fixtures/) into a directory outside the
 * repository, with fake secrets generated and each app committed to its own git repo.
 *
 *   npm run fixtures:build -- [--out <dir>] [--no-git]
 *
 * The default output is <os tmpdir>/vibeguard-fixtures. Building inside this repository is
 * refused: the repo's own .gitignore would apply to the apps and change scan results.
 */
import { tmpdir } from 'node:os';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { buildFixtures, FIXTURES_DIR } from '../test/helpers/fixtures.ts';

const { values } = parseArgs({
  options: {
    out: { type: 'string', default: path.join(tmpdir(), 'vibeguard-fixtures') },
    'no-git': { type: 'boolean', default: false },
  },
});
const out = path.resolve(values.out);
const repoRoot = path.dirname(FIXTURES_DIR);
if (!path.relative(repoRoot, out).startsWith('..')) {
  console.error(
    `Refusing to build fixtures inside the repository (${out}). Use --out <dir> elsewhere.`,
  );
  process.exit(2);
}
const built = await buildFixtures(out, { git: !values['no-git'] });
console.log(`Built ${built.apps.length} fixture apps into ${out}:`);
for (const app of built.apps) console.log(`  ${path.join(out, app)}`);
