// Portability check for the SQL parser, run in CI on Linux, macOS and Windows after
// `npm ci --ignore-scripts`: proves libpg-query needs no install script or native build.
// Plain JavaScript on purpose (no tsx/esbuild involved).
import assert from 'node:assert/strict';
import { loadModule, parseSync, scanSync } from 'libpg-query';

await loadModule();
const r = parseSync(
  'create table public.t (id int); alter table public.t enable row level security; create policy p on public.t for select using (auth.uid() = id);',
);
assert.equal(r.stmts?.length, 3);
assert.ok(r.stmts?.[2]?.stmt && 'CreatePolicyStmt' in r.stmts[2].stmt);
assert.throws(() => parseSync('alter table t enable row level securty;'));
assert.ok(scanSync('select 1; select 2;').tokens.some((t) => t.text === ';'));
console.log(`libpg-query OK on ${process.platform}/${process.arch}, Node ${process.version}`);
