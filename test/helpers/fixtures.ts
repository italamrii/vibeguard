import { execFileSync } from 'node:child_process';
import { mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { fake, isFakeKind, SECRET_KINDS } from './fake-secrets.ts';

/**
 * Fixture apps live in `fixtures/<app>/` as *templates* (ADR-0007):
 *  - `{{FAKE:<kind>[:<label>]}}` tokens are replaced with values from fake-secrets.ts;
 *  - path segments starting with `dot_` become dotfiles (`dot_env.local` → `.env.local`),
 *    so template .gitignore files do not affect this repository and template env files
 *    are not mistaken for real ones by tooling;
 *  - each materialised app becomes its own git repository with everything not ignored
 *    committed, so "committed" checks run against real git state.
 */

export const FIXTURES_DIR = path.resolve(import.meta.dirname, '../../fixtures');
const TOKEN = /\{\{FAKE:([a-z0-9_]+)(?::([a-z0-9_-]+))?\}\}/g;

export interface BuiltFixtures {
  readonly outDir: string;
  readonly apps: readonly string[];
  /** Every secret value substituted into any app (for redaction canary tests). */
  readonly secrets: readonly string[];
}

export function materialisedPath(templateRel: string): string {
  return templateRel
    .split('/')
    .map((seg) => (seg.startsWith('dot_') ? `.${seg.slice(4)}` : seg))
    .join('/');
}

export function renderTemplate(text: string, secrets: Set<string>): string {
  return text.replace(TOKEN, (_whole, kind: string, label: string | undefined) => {
    if (!isFakeKind(kind)) throw new Error(`Unknown fake kind in fixture: ${kind}`);
    const value = fake(kind, label ?? 'default');
    if (SECRET_KINDS.has(kind)) secrets.add(value);
    return value;
  });
}

async function listFiles(dir: string, rel = ''): Promise<string[]> {
  const out: string[] = [];
  for (const e of await readdir(path.join(dir, rel), { withFileTypes: true })) {
    const r = rel === '' ? e.name : `${rel}/${e.name}`;
    if (e.isDirectory()) out.push(...(await listFiles(dir, r)));
    else if (e.isFile()) out.push(r);
  }
  return out;
}

export async function buildFixtures(
  outDir: string,
  opts: { apps?: readonly string[]; git?: boolean } = {},
): Promise<BuiltFixtures> {
  const all = (await readdir(FIXTURES_DIR, { withFileTypes: true }))
    .filter((d) => d.isDirectory())
    .map((d) => d.name)
    .sort();
  const apps = opts.apps ?? all;
  const secrets = new Set<string>();
  await rm(outDir, { recursive: true, force: true });
  for (const app of apps) {
    const src = path.join(FIXTURES_DIR, app);
    const dest = path.join(outDir, app);
    for (const rel of await listFiles(src)) {
      const text = await readFile(path.join(src, rel), 'utf8');
      const target = path.join(dest, materialisedPath(rel));
      await mkdir(path.dirname(target), { recursive: true });
      await writeFile(target, renderTemplate(text, secrets));
    }
    if (opts.git !== false) commitAll(dest);
  }
  return { outDir, apps, secrets: [...secrets] };
}

function commitAll(dir: string): void {
  const git = (...args: string[]): void => {
    execFileSync(
      'git',
      [
        '-C',
        dir,
        '-c',
        'user.email=fixtures@example.invalid',
        '-c',
        'user.name=fixtures',
        '-c',
        'commit.gpgsign=false',
        '-c',
        'core.hooksPath=/dev/null',
        ...args,
      ],
      {
        stdio: 'ignore',
        env: { ...process.env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' },
      },
    );
  };
  git('init', '-q', '-b', 'main');
  git('add', '-A');
  git('commit', '-q', '-m', 'fixture');
}
