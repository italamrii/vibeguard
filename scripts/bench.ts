/**
 * Performance benchmark: generate a synthetic N-file project and time a full scan with
 * the real rule registry. Requires Node >= 22.18 (native TypeScript type stripping).
 *
 *   node scripts/bench.ts [--files 5000] [--keep]
 */
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { resolveSettings } from '../src/core/config/settings.ts';
import { scan } from '../src/core/engine/engine.ts';
import { ALL_RULES } from '../src/rules/index.ts';

const { values } = parseArgs({
  options: {
    files: { type: 'string', default: '5000' },
    keep: { type: 'boolean', default: false },
  },
});
const total = Number(values.files);

const component = (i: number): string => `'use client';
import { useState } from 'react';
import { Button } from '@/components/ui/button';

export function Widget${i}({ title }: { title: string }) {
  const [count, setCount] = useState(0);
  return (
    <div className="p-4 rounded-xl shadow">
      <h2>{title}</h2>
      <Button onClick={() => setCount((c) => c + 1)}>Clicked {count} times</Button>
    </div>
  );
}
`;
const route = (i: number): string => `import { NextResponse } from 'next/server';
import { createClient } from '@/lib/supabase/server';

export async function GET() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return NextResponse.json({ error: 'unauthorized' }, { status: 401 });
  const { data } = await supabase.from('items_${i}').select('*').eq('owner', user.id);
  return NextResponse.json(data);
}
`;
const util = (i: number): string => `export function format${i}(value: number): string {
  return new Intl.NumberFormat('en-US', { style: 'currency', currency: 'USD' }).format(value);
}
${'// filler line to make the file a realistic size\n'.repeat(40)}`;
const migration = (
  i: number,
): string => `create table public.t_${i} (id uuid primary key, owner uuid not null, body text);
alter table public.t_${i} enable row level security;
create policy "own rows" on public.t_${i} for select using (auth.uid() = owner);
`;

async function main(): Promise<void> {
  const root = await mkdtemp(path.join(tmpdir(), 'vg-bench-'));
  const write = async (rel: string, text: string): Promise<void> => {
    const abs = path.join(root, rel);
    await mkdir(path.dirname(abs), { recursive: true });
    await writeFile(abs, text);
  };
  const tasks: Promise<void>[] = [];
  for (let i = 0; i < total; i++) {
    const bucket = i % 10;
    const dir = `pkg${i % 50}`;
    if (bucket < 4) tasks.push(write(`src/components/${dir}/Widget${i}.tsx`, component(i)));
    else if (bucket < 6) tasks.push(write(`src/app/api/${dir}/r${i}/route.ts`, route(i)));
    else if (bucket < 9) tasks.push(write(`src/lib/${dir}/util${i}.ts`, util(i)));
    else
      tasks.push(
        write(`supabase/migrations/${String(20240101000000 + i)}_t${i}.sql`, migration(i)),
      );
  }
  // Noise that must be skipped quickly.
  for (let i = 0; i < 2000; i++)
    tasks.push(write(`node_modules/dep${i % 20}/f${i}.js`, 'module.exports = 1;\n'));
  await Promise.all(tasks);

  const t0 = performance.now();
  const result = await scan({ root, settings: resolveSettings(undefined), rules: ALL_RULES });
  const ms = performance.now() - t0;

  console.log(
    JSON.stringify(
      {
        files: result.filesScanned,
        rules: result.rules.length,
        findings: result.findings.length,
        complete: result.complete,
        ms: Math.round(ms),
        node: process.version,
      },
      null,
      2,
    ),
  );
  if (values.keep) console.log(`kept: ${root}`);
  else await rm(root, { recursive: true, force: true });
}

await main();
