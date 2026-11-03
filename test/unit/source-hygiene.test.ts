import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';

const repoRoot = path.resolve(import.meta.dirname, '../..');

function walk(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const abs = path.join(dir, name);
    return statSync(abs).isDirectory() ? walk(abs) : [abs];
  });
}

/**
 * A security tool's own source must be free of invisible bidi/format characters
 * ("Trojan Source"). Code that needs them must spell them as escapes.
 */
describe('source hygiene', () => {
  it('contains no invisible bidi or line-separator characters', () => {
    const offenders: string[] = [];
    const pattern = /[\u061c\u200b-\u200f\u202a-\u202e\u2066-\u2069\u2028\u2029\ufeff]/;
    for (const dir of ['src', 'test', 'scripts']) {
      let files: string[];
      try {
        files = walk(path.join(repoRoot, dir));
      } catch {
        continue;
      }
      for (const f of files.filter(
        (x) => /\.(ts|js|json|md)$/.test(x) && !x.includes('__snapshots__'),
      )) {
        if (pattern.test(readFileSync(f, 'utf8'))) offenders.push(path.relative(repoRoot, f));
      }
    }
    expect(offenders).toEqual([]);
  });
});

describe('docs', () => {
  it('lists every ADR file in docs/adr/README.md', () => {
    const dir = path.join(repoRoot, 'docs', 'adr');
    const index = readFileSync(path.join(dir, 'README.md'), 'utf8');
    const missing = readdirSync(dir).filter(
      (f) => /^\d{4}-.*\.md$/.test(f) && !index.includes(`(${f})`),
    );
    expect(missing).toEqual([]);
  });
});
