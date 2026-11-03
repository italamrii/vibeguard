import { execFileSync } from 'node:child_process';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { afterEach } from 'vitest';

const created: string[] = [];

/**
 * Create a throwaway project directory from a `{ relPath: content }` map. Directories
 * are removed after each test. Tests never write into the repository itself.
 */
export async function makeProject(files: Record<string, string | Buffer>): Promise<string> {
  const root = await mkdtemp(path.join(tmpdir(), 'vg-test-'));
  created.push(root);
  for (const [rel, content] of Object.entries(files)) {
    const abs = path.join(root, rel);
    await mkdir(path.dirname(abs), { recursive: true });
    await writeFile(abs, content);
  }
  return root;
}

export function gitInit(root: string, addPaths: readonly string[] = []): void {
  const git = (...args: string[]): void => {
    execFileSync(
      'git',
      ['-C', root, '-c', 'user.email=t@example.invalid', '-c', 'user.name=t', ...args],
      {
        stdio: 'ignore',
      },
    );
  };
  git('init', '-q');
  if (addPaths.length > 0) git('add', '-f', '--', ...addPaths);
}

afterEach(async () => {
  while (created.length > 0) {
    const dir = created.pop();
    if (dir) await rm(dir, { recursive: true, force: true });
  }
});
