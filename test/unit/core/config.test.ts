import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ConfigError, loadConfig } from '../../../src/core/config/load.ts';
import {
  isRuleEnabled,
  resolveSettings,
  severityOverride,
} from '../../../src/core/config/settings.ts';
import { makeProject } from '../../helpers/project.ts';

describe('loadConfig', () => {
  it('returns undefined when no config exists', async () => {
    const root = await makeProject({});
    expect(await loadConfig(root)).toEqual({ config: undefined, source: undefined });
  });

  it('loads and validates .vibeguard.yml', async () => {
    const root = await makeProject({
      '.vibeguard.yml': [
        'version: 1',
        'ignore: ["fixtures/**"]',
        'failOn: medium',
        'rules:',
        '  secrets/high-entropy: off',
        '  supabase/permissive-policy: { severity: low }',
        'endpoints:',
        '  authFunctions: [requireUser]',
      ].join('\n'),
    });
    const { config, source } = await loadConfig(root);
    expect(source).toBe(path.join(root, '.vibeguard.yml'));
    const s = resolveSettings(config, { failOn: 'critical' });
    expect(s.failOn).toBe('critical'); // CLI wins
    expect(s.ignore).toEqual(['fixtures/**']);
    expect(isRuleEnabled(s, 'secrets/high-entropy')).toBe(false);
    expect(isRuleEnabled(s, 'secrets/provider-key')).toBe(true);
    expect(severityOverride(s, 'supabase/permissive-policy')).toBe('low');
    expect(s.endpoints.authFunctions).toEqual(['requireUser']);
  });

  it.each([
    ['version: 2', /version/],
    ['version: 1\nrule: {}', /Unrecognized key/i],
    ['version: 1\nfailOn: severe', /failOn/],
    ['version: 1\nsupabase: { exposedSchema: [public] }', /Unrecognized key/i],
    ['version: [1', /Invalid YAML/],
  ])('rejects invalid config %j', async (yml, msg) => {
    const root = await makeProject({ '.vibeguard.yml': yml });
    await expect(loadConfig(root)).rejects.toThrow(ConfigError);
    await expect(loadConfig(root)).rejects.toThrow(msg);
  });

  it('fails loudly when an explicit --config path is missing', async () => {
    const root = await makeProject({});
    await expect(loadConfig(root, path.join(root, 'nope.yml'))).rejects.toThrow(/Cannot read/);
  });
});
