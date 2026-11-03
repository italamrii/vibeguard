import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import type { Finding } from '../../src/core/findings/finding.ts';

/**
 * Expected findings are declared next to the code they describe:
 *
 *   // vg-expect: secrets/provider-key
 *   const k = '…';
 *
 * The annotation applies to the next line that is not itself an annotation; stacking N
 * identical annotations expects N findings. `vg-expect-miss: <rule> -- <reason>` declares
 * a known false negative (counted against recall, documented in the threat model).
 *
 * Files that cannot hold comments (JSON, PEM) are annotated in `vg-expectations.txt` at
 * the app root, one per line:  `<path> | <substring on the target line> | <rule-id>`.
 */

export interface Expectation {
  readonly file: string;
  readonly line: number;
  readonly ruleId: string;
  readonly miss: boolean;
}

const ANNOTATION = /vg-expect(-miss)?:\s*([a-z0-9-]+\/[a-z0-9-]+)/;

async function walk(dir: string, rel = ''): Promise<string[]> {
  const out: string[] = [];
  for (const e of await readdir(path.join(dir, rel), { withFileTypes: true })) {
    if (e.name === '.git') continue;
    const r = rel === '' ? e.name : `${rel}/${e.name}`;
    if (e.isDirectory()) out.push(...(await walk(dir, r)));
    else out.push(r);
  }
  return out;
}

export async function readExpectations(appDir: string): Promise<Expectation[]> {
  const out: Expectation[] = [];
  const texts = new Map<string, string[]>();
  for (const file of await walk(appDir)) {
    const lines = (await readFile(path.join(appDir, file), 'utf8')).split(/\r?\n/);
    texts.set(file, lines);
    lines.forEach((text, i) => {
      const m = ANNOTATION.exec(text);
      if (!m || file === 'vg-expectations.txt') return;
      let target = i + 1;
      while (target < lines.length && ANNOTATION.test(lines[target] ?? '')) target++;
      out.push({ file, line: target + 1, ruleId: m[2] ?? '', miss: m[1] !== undefined });
    });
  }
  const sidecar = texts.get('vg-expectations.txt') ?? [];
  for (const raw of sidecar) {
    if (raw.trim() === '' || raw.startsWith('#')) continue;
    const [file, needle, ruleId] = raw.split('|').map((s) => s.trim());
    const lines = file === undefined ? undefined : texts.get(file);
    const idx = lines?.findIndex((l) => needle !== undefined && l.includes(needle)) ?? -1;
    if (!file || !ruleId || idx === -1) throw new Error(`Bad vg-expectations.txt line: ${raw}`);
    out.push({ file, line: idx + 1, ruleId, miss: false });
  }
  return out;
}

export interface RuleScore {
  tp: number;
  fp: number;
  fn: number;
  knownMisses: number;
}

export interface Comparison {
  readonly byRule: Map<string, RuleScore>;
  readonly falsePositives: Finding[];
  readonly falseNegatives: Expectation[];
}

/** Match unsuppressed findings to expectations on (rule, file, line). */
export function compare(
  expectations: readonly Expectation[],
  findings: readonly Finding[],
): Comparison {
  const byRule = new Map<string, RuleScore>();
  const score = (rule: string): RuleScore => {
    let s = byRule.get(rule);
    if (!s) {
      s = { tp: 0, fp: 0, fn: 0, knownMisses: 0 };
      byRule.set(rule, s);
    }
    return s;
  };
  const open = expectations.filter((e) => !e.miss).map((e) => ({ e, used: false }));
  const falsePositives: Finding[] = [];
  for (const f of findings.filter((x) => !x.suppression)) {
    const hit = open.find(
      (o) =>
        !o.used &&
        o.e.ruleId === f.ruleId &&
        o.e.file === f.location.file &&
        o.e.line === f.location.line,
    );
    if (hit) {
      hit.used = true;
      score(f.ruleId).tp++;
    } else {
      score(f.ruleId).fp++;
      falsePositives.push(f);
    }
  }
  const falseNegatives = open.filter((o) => !o.used).map((o) => o.e);
  for (const e of falseNegatives) score(e.ruleId).fn++;
  for (const e of expectations.filter((x) => x.miss)) {
    score(e.ruleId).fn++;
    score(e.ruleId).knownMisses++;
  }
  return { byRule, falsePositives, falseNegatives };
}

export function precision(s: RuleScore): number {
  return s.tp + s.fp === 0 ? 1 : s.tp / (s.tp + s.fp);
}

export function recall(s: RuleScore): number {
  return s.tp + s.fn === 0 ? 1 : s.tp / (s.tp + s.fn);
}
