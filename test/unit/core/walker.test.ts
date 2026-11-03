import { symlink } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { discoverFiles } from '../../../src/core/discovery/walker.ts';
import { gitInit, makeProject } from '../../helpers/project.ts';

const rels = async (
  root: string,
  opts: { ignorePatterns?: string[]; maxFileBytes?: number } = {},
) => (await discoverFiles({ root, ...opts })).files.map((f) => f.relPath);

describe('discoverFiles', () => {
  it('skips dependency and build directories, binaries, lockfiles and minified bundles', async () => {
    const root = await makeProject({
      'src/a.ts': 'x',
      'node_modules/pkg/index.js': 'x',
      '.next/server/page.js': 'x',
      'dist/out.js': 'x',
      'public/logo.png': 'x',
      'package-lock.json': '{}',
      'public/vendor.min.js': 'x',
      'README.md': 'x',
    });
    expect(await rels(root)).toEqual(['README.md', 'src/a.ts']);
  });

  it('respects nested .gitignore files and negations', async () => {
    const root = await makeProject({
      '.gitignore': 'generated/\n*.log\n',
      'app.log': 'x',
      'generated/x.ts': 'x',
      'pkg/.gitignore': 'tmp-*\n!tmp-keep.ts\n',
      'pkg/tmp-1.ts': 'x',
      'pkg/tmp-keep.ts': 'x',
      'pkg/main.ts': 'x',
    });
    expect(await rels(root)).toEqual([
      '.gitignore',
      'pkg/.gitignore',
      'pkg/main.ts',
      'pkg/tmp-keep.ts',
    ]);
  });

  it('keeps gitignored env files but marks them', async () => {
    const root = await makeProject({ '.gitignore': '.env*\n', '.env.local': 'A=1', 'a.ts': 'x' });
    const { files } = await discoverFiles({ root });
    const env = files.find((f) => f.relPath === '.env.local');
    expect(env).toMatchObject({ kind: 'env', gitIgnored: true, gitTracked: undefined });
  });

  it('applies config ignore patterns', async () => {
    const root = await makeProject({ 'a.ts': 'x', 'fixtures/b.ts': 'x', 'c.test.ts': 'x' });
    expect(await rels(root, { ignorePatterns: ['fixtures/', '*.test.ts'] })).toEqual(['a.ts']);
  });

  it('does not follow symlinks', async () => {
    const outside = await makeProject({ 'secret.ts': 'x' });
    const root = await makeProject({ 'a.ts': 'x' });
    await symlink(outside, path.join(root, 'linked'));
    const result = await discoverFiles({ root });
    expect(result.files.map((f) => f.relPath)).toEqual(['a.ts']);
    expect(result.diagnostics).toContainEqual(
      expect.objectContaining({ code: 'symlink-skipped', file: 'linked' }),
    );
  });

  it('skips files above the size limit with a diagnostic', async () => {
    const root = await makeProject({ 'big.ts': 'x'.repeat(2000), 'small.ts': 'x' });
    const result = await discoverFiles({ root, maxFileBytes: 1000 });
    expect(result.files.map((f) => f.relPath)).toEqual(['small.ts']);
    expect(result.diagnostics).toContainEqual(
      expect.objectContaining({ code: 'file-too-large', file: 'big.ts' }),
    );
  });

  it('reports git-tracked status, including force-added files in ignored directories', async () => {
    const root = await makeProject({
      '.gitignore': '.env\nsecrets/\n',
      '.env': 'A=1',
      'secrets/prod.env': 'B=2',
      'a.ts': 'x',
      'untracked.ts': 'x',
    });
    gitInit(root, ['.env', 'secrets/prod.env', 'a.ts', '.gitignore']);
    const { files } = await discoverFiles({ root });
    const by = Object.fromEntries(files.map((f) => [f.relPath, f]));
    expect(by['.env']).toMatchObject({ gitTracked: true, gitIgnored: true });
    expect(by['secrets/prod.env']).toMatchObject({ gitTracked: true, gitIgnored: true });
    expect(by['a.ts']?.gitTracked).toBe(true);
    expect(by['untracked.ts']?.gitTracked).toBe(false);
  });

  it('applies .gitignore files above the scan root inside the same repo', async () => {
    const repo = await makeProject({
      '.gitignore': 'apps/web/generated/\n',
      'apps/web/generated/x.ts': 'x',
      'apps/web/a.ts': 'x',
    });
    gitInit(repo);
    expect(await rels(path.join(repo, 'apps/web'))).toEqual(['a.ts']);
  });

  it('rejects a non-directory root', async () => {
    const root = await makeProject({ 'a.ts': 'x' });
    await expect(discoverFiles({ root: path.join(root, 'a.ts') })).rejects.toThrow(
      /not a directory/,
    );
  });
});
