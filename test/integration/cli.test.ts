import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { run } from '../../src/cli/run.ts';
import type { Rule } from '../../src/core/engine/rule.ts';
import { makeProject } from '../helpers/project.ts';
import { crashingRule, markerRule } from '../helpers/test-rules.ts';

async function cli(args: string[], rules: readonly Rule[] = [markerRule], cwd = process.cwd()) {
  let stdout = '';
  let stderr = '';
  const code = await run(
    args,
    {
      stdout: (s) => (stdout += s),
      stderr: (s) => (stderr += s),
      stdoutIsTTY: false,
      env: {},
      cwd,
    },
    { rules },
  );
  return { code, stdout, stderr };
}

describe('vibeguard CLI', () => {
  it('shows the own-code notice in --help', async () => {
    const { code, stdout } = await cli(['--help']);
    expect(code).toBe(0);
    expect(stdout).toContain('Scan only code you own or are authorized to assess.');
    const scanHelp = await cli(['scan', '--help']);
    expect(scanHelp.stdout).toContain('Scan only code you own or are authorized to assess.');
  });

  it('exits 0 for a clean project', async () => {
    const root = await makeProject({ 'a.ts': 'clean' });
    const r = await cli(['scan', root]);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('No findings.');
  });

  it('exits 1 when findings meet --fail-on, 0 when they do not', async () => {
    const root = await makeProject({ 'a.ts': 'VG_TEST_MARKER:high:medium' });
    expect((await cli(['scan', root])).code).toBe(0); // default fail-on high
    expect((await cli(['scan', root, '--fail-on', 'medium'])).code).toBe(1);
    expect((await cli(['scan', root, '--fail-on', 'none'])).code).toBe(0);
  });

  it('honours failOn from config, overridden by the flag', async () => {
    const root = await makeProject({
      'a.ts': 'VG_TEST_MARKER:high:low',
      '.vibeguard.yml': 'version: 1\nfailOn: low\n',
    });
    expect((await cli(['scan', root])).code).toBe(1);
    expect((await cli(['scan', root, '--fail-on', 'high'])).code).toBe(0);
  });

  it('exits 3 when a rule crashes, even with no findings', async () => {
    const root = await makeProject({ 'a.ts': 'clean' });
    const r = await cli(['scan', root], [markerRule, crashingRule]);
    expect(r.code).toBe(3);
    expect(r.stdout).toContain('SCAN INCOMPLETE');
  });

  it.each([
    [['scan', '--format', 'xml']],
    [['scan', '--lang', 'fr']],
    [['scan', '--fail-on', 'severe']],
    [['scan', '/definitely/not/here']],
    [['bogus']],
  ])('exits 2 on usage errors: %j', async (args) => {
    expect((await cli(args)).code).toBe(2);
  });

  it('exits 2 on an invalid config or unknown rule id in config', async () => {
    const bad = await makeProject({ '.vibeguard.yml': 'version: 1\nfailOn: nope\n' });
    expect((await cli(['scan', bad])).code).toBe(2);
    const unknown = await makeProject({
      '.vibeguard.yml': 'version: 1\nrules: { nope/rule: off }\n',
    });
    const r = await cli(['scan', unknown]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain('nope/rule');
  });

  it('refuses to write the report inside the scanned project', async () => {
    const root = await makeProject({ 'a.ts': 'x' });
    const r = await cli([
      'scan',
      root,
      '--output',
      path.join(root, 'report.json'),
      '--format',
      'json',
    ]);
    expect(r.code).toBe(2);
    expect(r.stderr).toContain('refusing to write');
    const relative = await cli(
      ['scan', '.', '--output', 'sub/dir/report.json'],
      [markerRule],
      root,
    );
    expect(relative.code).toBe(2);
  });

  it('writes the report to a path outside the project', async () => {
    const root = await makeProject({ 'a.ts': 'VG_TEST_MARKER' });
    const outDir = await mkdtemp(path.join(tmpdir(), 'vg-out-'));
    try {
      const out = path.join(outDir, 'r.json');
      const r = await cli(['scan', root, '--format', 'json', '--output', out, '--fail-on', 'none']);
      expect(r.code).toBe(0);
      expect(r.stdout).toBe('');
      const doc = JSON.parse(await readFile(out, 'utf8')) as { findings: unknown[] };
      expect(doc.findings).toHaveLength(1);
    } finally {
      await rm(outDir, { recursive: true, force: true });
    }
  });

  it('lists rules', async () => {
    const r = await cli(['rules']);
    expect(r.code).toBe(0);
    expect(r.stdout).toContain('test/marker');
  });
});

describe('Arabic in the terminal (ADR-0013)', () => {
  it('prints a bilingual hint and an English report for --lang ar with terminal output', async () => {
    const root = await makeProject({ 'a.ts': 'VG_TEST_MARKER' });
    const r = await cli(['scan', root, '--lang', 'ar', '--fail-on', 'none']);
    expect(r.stdout).toContain('Arabic is not shown in the terminal');
    expect(r.stdout).toContain('لا تُعرض اللغة العربية في الطرفية');
    expect(r.stdout).toContain('VibeGuard security report');
  });

  it('prints CLI errors in English, then Arabic, with --lang ar', async () => {
    const r = await cli(['scan', '/definitely/not/here', '--lang', 'ar']);
    expect(r.code).toBe(2);
    expect(r.stderr).toBe(
      'vibeguard: path not found: /definitely/not/here\nvibeguard: المسار غير موجود: /definitely/not/here\n',
    );
  });

  it('keeps Arabic for file formats', async () => {
    const root = await makeProject({ 'a.ts': 'VG_TEST_MARKER' });
    const r = await cli([
      'scan',
      root,
      '--lang',
      'ar',
      '--format',
      'markdown',
      '--fail-on',
      'none',
    ]);
    expect(r.stdout.startsWith('<div dir="rtl">')).toBe(true);
  });
});
