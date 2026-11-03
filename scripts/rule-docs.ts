/**
 * Generate docs/rules/<rule-id>.md and docs/rules/README.md from the rule registry.
 *
 *   npm run docs:rules             # write pages (hand-written regions are kept)
 *   npm run docs:rules -- --check  # CI: fail if a page is stale, missing, orphaned, or has
 *                                  # an unwritten hand region
 */
import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { format, resolveConfig } from 'prettier';
import { ALL_RULES } from '../src/rules/index.ts';
import {
  extractHandRegions,
  HAND_REGIONS,
  isPlaceholder,
  renderIndex,
  renderRulePage,
  RULE_DOCS_DIR,
  rulePagePath,
} from './lib/rule-docs.ts';

const { values } = parseArgs({ options: { check: { type: 'boolean', default: false } } });

async function pretty(file: string, text: string): Promise<string> {
  return format(text, { ...(await resolveConfig(file)), parser: 'markdown', filepath: file });
}

const problems: string[] = [];
const expected = new Map<string, string>();
for (const rule of ALL_RULES) {
  const file = rulePagePath(rule.meta.id);
  const current = await readFile(file, 'utf8').catch(() => '');
  const hand = extractHandRegions(current);
  for (const r of HAND_REGIONS)
    if (isPlaceholder(hand[r])) problems.push(`${file}: hand region "${r}" is not written`);
  expected.set(file, await pretty(file, renderRulePage(rule.meta, hand)));
}
const indexFile = `${RULE_DOCS_DIR}/README.md`;
expected.set(indexFile, await pretty(indexFile, renderIndex(ALL_RULES.map((r) => r.meta))));

// Orphans: pages for rules that no longer exist.
for (const family of await readdir(RULE_DOCS_DIR, { withFileTypes: true }).catch(() => [])) {
  if (!family.isDirectory()) continue;
  for (const f of await readdir(path.join(RULE_DOCS_DIR, family.name))) {
    const p = `${RULE_DOCS_DIR}/${family.name}/${f}`;
    if (!expected.has(p)) problems.push(`${p}: no rule with this id (orphaned page)`);
  }
}

for (const [file, text] of expected) {
  if (values.check) {
    const current = await readFile(file, 'utf8').catch(() => '');
    if (current !== text) problems.push(`${file} is stale or missing: run npm run docs:rules`);
  } else {
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, text);
  }
}

console.log(`rule docs: ${ALL_RULES.length} rules, ${problems.length} problem(s)`);
for (const p of problems) console.error(`  - ${p}`);
if (problems.length > 0) process.exitCode = 1;
