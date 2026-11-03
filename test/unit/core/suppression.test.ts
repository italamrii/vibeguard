import { describe, expect, it } from 'vitest';
import { findSuppression, parseSuppressions } from '../../../src/core/suppression/suppression.ts';

const known = new Set(['secrets/provider-key', 'supabase/rls-disabled']);
const parse = (src: string) => parseSuppressions(src.split('\n'), known);

describe('parseSuppressions', () => {
  it('parses next-line directives in JS comments', () => {
    const p = parse(
      '// vibeguard-ignore-next-line secrets/provider-key -- test key, revoked in 2024\nconst k = 1;',
    );
    expect(p.invalid).toEqual([]);
    expect(p.directives).toEqual([
      {
        kind: 'next-line',
        ruleIds: ['secrets/provider-key'],
        reason: 'test key, revoked in 2024',
        line: 1,
        targetLine: 2,
      },
    ]);
  });

  it('works in SQL, shell/env, block and JSX comments', () => {
    const src = [
      '-- vibeguard-ignore-next-line supabase/rls-disabled -- public lookup table, read-only',
      'create table public.countries (id int);',
      'KEY=1 # vibeguard-ignore-line secrets/provider-key -- documented sample value',
      '/* vibeguard-ignore-line secrets/provider-key -- documented sample value */',
      '{/* vibeguard-ignore-line secrets/provider-key -- documented sample value */}',
    ].join('\n');
    const p = parse(src);
    expect(p.invalid).toEqual([]);
    expect(p.directives.map((d) => [d.targetLine, d.reason])).toEqual([
      [2, 'public lookup table, read-only'],
      [3, 'documented sample value'],
      [4, 'documented sample value'],
      [5, 'documented sample value'],
    ]);
  });

  it('accepts several rule ids', () => {
    const p = parse(
      '// vibeguard-ignore-file secrets/provider-key, supabase/rls-disabled -- generated fixture file',
    );
    expect(p.directives[0]?.ruleIds).toEqual(['secrets/provider-key', 'supabase/rls-disabled']);
    expect(p.directives[0]?.targetLine).toBe(0);
  });

  it('skips over stacked directives for next-line', () => {
    const p = parse(
      [
        '// vibeguard-ignore-next-line secrets/provider-key -- reason number one',
        '// vibeguard-ignore-next-line supabase/rls-disabled -- reason number two',
        'code();',
      ].join('\n'),
    );
    expect(p.directives.map((d) => d.targetLine)).toEqual([3, 3]);
  });

  it.each([
    ['// vibeguard-ignore-next-line secrets/provider-key', 'missing-reason'],
    ['// vibeguard-ignore-next-line secrets/provider-key --', 'missing-reason'],
    ['// vibeguard-ignore-next-line secrets/provider-key -- ok', 'reason-too-short'],
    ['// vibeguard-ignore-next-line -- because I said so', 'missing-rule-id'],
    ['// vibeguard-ignore-next-line secrets/nope -- because I said so', 'unknown-rule-id'],
    ['// vibeguard-ignore-next-line * -- blanket suppressions are not allowed', 'unknown-rule-id'],
  ])('rejects %s', (line, problem) => {
    const p = parse(line);
    expect(p.directives).toEqual([]);
    expect(p.invalid[0]?.problem).toBe(problem);
  });
});

describe('findSuppression', () => {
  it('matches only the named rule on the target line', () => {
    const p = parse('x // vibeguard-ignore-line secrets/provider-key -- fixture data only');
    expect(findSuppression(p, 'secrets/provider-key', 1)).toBeDefined();
    expect(findSuppression(p, 'secrets/provider-key', 2)).toBeUndefined();
    expect(findSuppression(p, 'supabase/rls-disabled', 1)).toBeUndefined();
  });
});
