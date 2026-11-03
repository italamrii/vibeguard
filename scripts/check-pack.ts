/**
 * Release gate for the npm tarball (run in CI on every push).
 *
 *  1. `npm pack --dry-run --json`: every file must match the allowlist below, and the
 *     required files must be present. Fixtures, templates, tests, scripts, sources, source
 *     maps, env files and anything else not allowlisted fail the check.
 *  2. The tarball is packed for real into a temp dir, unpacked, and every file is run
 *     through VibeGuard's own secret signatures and PEM detector. Any hit fails.
 *
 * Prints the file list (paths and sizes only).
 *
 *   npm run pack:check            # check only
 *   npm run pack:check -- --keep <dir>   # also leave the .tgz in <dir> (used by CI)
 */
import { execFileSync } from 'node:child_process';
import { copyFileSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, relative } from 'node:path';
import { findPemPrivateKeys } from '../src/rules/secrets/private-key.rule.ts';
import { findSecrets } from '../src/rules/secrets/patterns.ts';

const ALLOWED: readonly RegExp[] = [
  /^package\.json$/,
  /^README\.md$/,
  /^LICENSE$/,
  /^NOTICE$/,
  /^schema\/[a-z0-9.-]+\.schema\.json$/,
  /^dist\/[a-z0-9/_-]+(\.rule)?\.js$/,
];
const REQUIRED = ['package.json', 'README.md', 'LICENSE', 'NOTICE', 'dist/cli/index.js'];
// Defence in depth: even if the allowlist were loosened, these may never ship.
const FORBIDDEN =
  /(^|\/)(fixtures|templates|test|tests|scripts|src|coverage|\.github|docs)\/|(^|\/)\.env|\.(ts|map|tgz|pem|key|p12)$|(^|\/)\.vibeguard\.yml$/;

interface PackEntry {
  path: string;
  size: number;
}
interface PackResult {
  filename: string;
  size: number;
  unpackedSize: number;
  files: PackEntry[];
}

const npm = process.platform === 'win32' ? 'npm.cmd' : 'npm';
const keepIdx = process.argv.indexOf('--keep');
const keepDir = keepIdx >= 0 ? process.argv[keepIdx + 1] : undefined;

function pack(args: readonly string[]): PackResult {
  // --ignore-scripts: `prepack` would rebuild; the caller builds first.
  const out = execFileSync(npm, ['pack', '--json', '--ignore-scripts', ...args], {
    encoding: 'utf8',
  });
  const parsed = JSON.parse(out) as PackResult[];
  const first = parsed[0];
  if (!first) throw new Error('npm pack returned no result');
  return first;
}

const problems: string[] = [];
const dry = pack(['--dry-run']);
const paths = dry.files.map((f) => f.path).sort();
for (const p of paths) {
  if (!ALLOWED.some((re) => re.test(p))) problems.push(`not allowlisted: ${p}`);
  if (FORBIDDEN.test(p)) problems.push(`forbidden path: ${p}`);
}
for (const r of REQUIRED) if (!paths.includes(r)) problems.push(`missing required file: ${r}`);

const work = mkdtempSync(join(tmpdir(), 'vg-pack-'));
try {
  const real = pack(['--pack-destination', work]);
  const tgz = join(work, real.filename);
  execFileSync('tar', ['-xzf', tgz, '-C', work]);
  // npm tarballs unpack into "package/".
  const root = join(work, 'package');
  let secretHits = 0;
  const walk = (dir: string): void => {
    for (const name of readdirSync(dir)) {
      const abs = join(dir, name);
      if (statSync(abs).isDirectory()) {
        walk(abs);
        continue;
      }
      const text = readFileSync(abs, 'utf8');
      const hits = findPemPrivateKeys(text).length + text.split('\n').flatMap(findSecrets).length;
      if (hits > 0) {
        secretHits += hits;
        problems.push(`secret-shaped content in ${relative(root, abs)} (${hits} match(es))`);
      }
    }
  };
  walk(root);
  console.log(
    `tarball: ${real.filename} (${real.size} bytes packed, ${real.unpackedSize} unpacked)`,
  );
  console.log(`files: ${paths.length} | secret-shaped strings in tarball: ${secretHits}`);
  if (keepDir) copyFileSync(tgz, join(keepDir, real.filename));
} finally {
  rmSync(work, { recursive: true, force: true });
}
for (const f of [...dry.files].sort((a, b) => a.path.localeCompare(b.path)))
  console.log(`  ${String(f.size).padStart(7)}  ${f.path}`);

if (problems.length > 0) {
  console.error(`\npack check FAILED (${problems.length} problem(s)):`);
  for (const p of problems) console.error(`  - ${p}`);
  process.exitCode = 1;
} else {
  console.log('\npack check passed: allowlist only, no secret-shaped content.');
}
