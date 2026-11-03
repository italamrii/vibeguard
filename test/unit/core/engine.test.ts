import { describe, expect, it } from 'vitest';
import { resolveSettings } from '../../../src/core/config/settings.ts';
import { RuleRegistryError, scan, validateRules } from '../../../src/core/engine/engine.ts';
import { badMessageRule, crashingRule, markerRule } from '../../helpers/test-rules.ts';
import { makeProject } from '../../helpers/project.ts';

const settings = resolveSettings(undefined);

describe('scan', () => {
  it('materialises findings with rule metadata, sorted by severity then location', async () => {
    const root = await makeProject({
      'b.ts': 'x\nVG_TEST_MARKER:high:low',
      'a.ts': 'VG_TEST_MARKER',
      'c.ts': 'VG_TEST_MARKER:high:critical',
    });
    const r = await scan({ root, settings, rules: [markerRule] });
    expect(r.complete).toBe(true);
    expect(r.filesScanned).toBe(3);
    expect(r.findings.map((f) => [f.location.file, f.severity])).toEqual([
      ['c.ts', 'critical'],
      ['a.ts', 'high'],
      ['b.ts', 'low'],
    ]);
    expect(r.findings[0]).toMatchObject({
      ruleId: 'test/marker',
      cwe: [1],
      params: { name: 'c.ts' },
    });
  });

  it('produces fingerprints that survive line shifts', async () => {
    const a = await makeProject({ 'a.ts': 'VG_TEST_MARKER' });
    const b = await makeProject({ 'a.ts': '\n\n\nVG_TEST_MARKER' });
    const fa = (await scan({ root: a, settings, rules: [markerRule] })).findings[0]?.fingerprint;
    const fb = (await scan({ root: b, settings, rules: [markerRule] })).findings[0]?.fingerprint;
    expect(fa).toMatch(/^[0-9a-f]{32}$/);
    expect(fa).toBe(fb);
  });

  it('isolates a crashing rule, marks the scan incomplete and scrubs the error', async () => {
    const root = await makeProject({ 'a.ts': 'VG_TEST_MARKER' });
    const r = await scan({ root, settings, rules: [markerRule, crashingRule] });
    expect(r.complete).toBe(false);
    expect(r.findings).toHaveLength(1);
    const d = r.diagnostics.find((x) => x.code === 'rule-crashed');
    expect(d?.params['rule']).toBe('test/crash');
    expect(String(d?.params['error'])).not.toContain('51HxQabcdefghijklmnopqrstuv');
  });

  it('treats an unknown messageId as a rule bug (incomplete scan)', async () => {
    const root = await makeProject({ 'a.txt': 'x' });
    const r = await scan({ root, settings, rules: [badMessageRule] });
    expect(r.complete).toBe(false);
    expect(r.findings).toEqual([]);
  });

  it('applies suppressions with reasons and reports invalid and unused ones', async () => {
    const root = await makeProject({
      'a.ts': [
        '// vibeguard-ignore-next-line test/marker -- intentional test marker here',
        'VG_TEST_MARKER one',
        '// vibeguard-ignore-next-line test/marker',
        'VG_TEST_MARKER two',
        '// vibeguard-ignore-next-line test/marker -- nothing on the next line',
        'clean();',
      ].join('\n'),
    });
    const r = await scan({ root, settings, rules: [markerRule] });
    const [first, second] = r.findings;
    expect(first?.suppression).toEqual({ reason: 'intentional test marker here', line: 1 });
    expect(second?.suppression).toBeUndefined();
    expect(r.diagnostics.map((d) => [d.code, d.line])).toEqual([
      ['invalid-suppression', 3],
      ['unused-suppression', 5],
    ]);
    expect(r.complete).toBe(true); // warnings do not make a scan incomplete
  });

  it('honours rule toggles, severity overrides and minConfidence', async () => {
    const root = await makeProject({ 'a.ts': 'VG_TEST_MARKER:low\nVG_TEST_MARKER:high' });
    const off = await scan({
      root,
      settings: resolveSettings({ version: 1, rules: { 'test/marker': 'off' } }),
      rules: [markerRule],
    });
    expect(off.findings).toEqual([]);
    expect(off.rules).toEqual([]);

    const over = await scan({
      root,
      settings: resolveSettings({ version: 1, rules: { 'test/marker': { severity: 'low' } } }),
      rules: [markerRule],
    });
    expect(over.findings.every((f) => f.severity === 'low')).toBe(true);

    const conf = await scan({
      root,
      settings: resolveSettings(undefined, { minConfidence: 'medium' }),
      rules: [markerRule],
    });
    expect(conf.findings).toHaveLength(1);
    expect(conf.belowConfidenceThreshold).toBe(1);
  });
});

describe('validateRules', () => {
  it('rejects malformed and duplicate rule ids', () => {
    expect(() => {
      validateRules([markerRule, markerRule]);
    }).toThrow(RuleRegistryError);
    expect(() => {
      validateRules([{ ...markerRule, meta: { ...markerRule.meta, id: 'Bad Id' } }]);
    }).toThrow(/Invalid rule id/);
    expect(() => {
      validateRules([{ ...markerRule, meta: { ...markerRule.meta, family: 'other' } }]);
    }).toThrow(/family/);
  });
});
