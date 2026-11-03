/**
 * Scan every line ever added in the repository's history (all refs) for secret-shaped
 * strings, using VibeGuard's own provider signatures, PEM detection and JWT classification.
 * Prints counts only, never the matched values.
 *
 *   npm run scan:history
 */
import { execFileSync } from 'node:child_process';
import { findPemPrivateKeys } from '../src/rules/secrets/private-key.rule.ts';
import { findSecrets } from '../src/rules/secrets/patterns.ts';

const log = execFileSync(
  'git',
  ['log', '-p', '--all', '--no-color', '--no-ext-diff', '--format=commit %H'],
  {
    maxBuffer: 512 * 1024 * 1024,
    encoding: 'utf8',
  },
);
const commits = new Set<string>();
let commit = '';
let addedLines = 0;
const byPattern = new Map<string, { hits: number; commits: Set<string> }>();
const record = (id: string): void => {
  const e = byPattern.get(id) ?? { hits: 0, commits: new Set<string>() };
  e.hits++;
  e.commits.add(commit);
  byPattern.set(id, e);
};
let block: string[] = [];
const flushBlock = (): void => {
  if (block.length > 0) {
    const n = findPemPrivateKeys(block.join('\n')).length;
    for (let i = 0; i < n; i++) record('pem-private-key');
  }
  block = [];
};
for (const line of log.split('\n')) {
  if (line.startsWith('commit ')) {
    flushBlock();
    commit = line.slice(7);
    commits.add(commit);
    continue;
  }
  if (!line.startsWith('+') || line.startsWith('+++')) {
    flushBlock();
    continue;
  }
  addedLines++;
  const text = line.slice(1);
  block.push(text);
  for (const m of findSecrets(text)) record(m.patternId);
}
flushBlock();
console.log(`refs: all | commits scanned: ${commits.size} | added lines scanned: ${addedLines}`);
if (byPattern.size === 0) console.log('secret-shaped strings found: 0');
for (const [id, e] of byPattern)
  console.log(`${id}: ${e.hits} match(es) in ${e.commits.size} commit(s)`);
process.exitCode = byPattern.size === 0 ? 0 : 1;
