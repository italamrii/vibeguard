import { describe, expect, it } from 'vitest';
import { resolveSettings } from '../../../../src/core/config/settings.ts';
import { scan } from '../../../../src/core/engine/engine.ts';
import type { Rule } from '../../../../src/core/engine/rule.ts';
import {
  classifyExposedName,
  clientExposedEnvRule,
} from '../../../../src/rules/secrets/client-exposed-env.rule.ts';
import { parseEnvLines } from '../../../../src/rules/secrets/env-file.ts';
import { envFileCommittedRule } from '../../../../src/rules/secrets/env-file-committed.rule.ts';
import {
  classifyCandidate,
  highEntropyRule,
  nameWords,
} from '../../../../src/rules/secrets/high-entropy.rule.ts';
import { privateKeyRule } from '../../../../src/rules/secrets/private-key.rule.ts';
import { providerKeyRule } from '../../../../src/rules/secrets/provider-key.rule.ts';
import { fake } from '../../../helpers/fake-secrets.ts';
import { gitInit, makeProject } from '../../../helpers/project.ts';

const j = (...p: string[]): string => p.join('');

async function run(rule: Rule, files: Record<string, string>, git?: readonly string[]) {
  const root = await makeProject(files);
  if (git) gitInit(root, git);
  const r = await scan({ root, settings: resolveSettings(undefined), rules: [rule] });
  expect(r.complete).toBe(true);
  return r.findings;
}

describe('secrets/provider-key', () => {
  it('reports location, redacted evidence and provider', async () => {
    const key = fake('stripe_live', 'r1');
    const [f, ...rest] = await run(providerKeyRule, {
      'src/a.ts': `\nconst s = new Stripe('${key}');`,
    });
    expect(rest).toEqual([]);
    expect(f).toMatchObject({
      ruleId: 'secrets/provider-key',
      severity: 'critical',
      confidence: 'high',
      location: { file: 'src/a.ts', line: 2, column: 23 },
      params: { provider: 'Stripe live secret key' },
      evidence: `${key.slice(0, 4)}…[${key.length} chars]`,
    });
  });

  it('ignores gitignored, untracked env files (the right place for local secrets)', async () => {
    const files = {
      '.gitignore': '.env.local\n',
      '.env.local': `STRIPE=${fake('stripe_live', 'r2')}`,
    };
    expect(await run(providerKeyRule, files)).toEqual([]);
    expect(await run(providerKeyRule, files, ['.gitignore'])).toEqual([]);
  });

  it('reports env files that are tracked even though they are gitignored now', async () => {
    const files = { '.gitignore': '.env\n', '.env': `STRIPE=${fake('stripe_live', 'r3')}` };
    expect(await run(providerKeyRule, files, ['.env', '.gitignore'])).toHaveLength(1);
  });

  it('lowers confidence in test code instead of hiding the finding', async () => {
    const [f] = await run(providerKeyRule, {
      'src/__tests__/pay.test.ts': `const k = '${fake('stripe_live', 'r4')}';`,
    });
    expect(f?.confidence).toBe('medium');
  });

  it('streams files above the in-memory threshold', async () => {
    const big = `${'// filler line\n'.repeat(80_000)}const k = '${fake('github_classic', 'r5')}';\n`;
    expect(big.length).toBeGreaterThan(1024 * 1024);
    const [f] = await run(providerKeyRule, { 'big.js': big });
    expect(f?.location.line).toBe(80_001);
  });
});

describe('secrets/private-key', () => {
  it('detects PEM keys and redacts the body', async () => {
    const pem = fake('pem_rsa', 'k1');
    const [f] = await run(privateKeyRule, { 'certs/server.key': pem });
    expect(f).toMatchObject({ messageId: 'pemKey', severity: 'critical', location: { line: 1 } });
    expect(f?.evidence).toMatch(/^RSA PRIVATE KEY: [A-Za-z0-9+/]{4}…\[\d+ chars\]$/);
  });

  it('ignores documentation snippets without a real body', async () => {
    const doc = j('-----BEGIN ', 'PRIVATE KEY-----\n...\n-----END ', 'PRIVATE KEY-----\n');
    const doc2 = j(
      '-----BEGIN ',
      'RSA PRIVATE KEY-----\nMIIE<your key here>\n-----END ',
      'RSA PRIVATE KEY-----',
    );
    expect(
      await run(privateKeyRule, { 'README.md': `Put your key here:\n${doc}\n${doc2}` }),
    ).toEqual([]);
  });

  it('does not treat code following a PEM header string as a key body (regression)', async () => {
    const header = j('-----BEGIN ', 'PRIVATE KEY-----');
    const src = [
      `const input = '${header}' + 'A'.repeat(100_000);`,
      'const anotherVeryLongIdentifierName = someFunctionCall(argumentNumberOne, argumentTwo);',
      'export const AnotherExportedValueWithLongName = buildTheThing(configurationObject);',
    ].join('\n');
    expect(await run(privateKeyRule, { 'src/redos.test.ts': src })).toEqual([]);
  });

  it('detects keys embedded in code as concatenated or escaped strings', async () => {
    const lines = fake('pem_rsa', 'k4').split('\n');
    const concatenated = `const key =\n${lines.map((l) => `  '${l}\\n' +`).join('\n')}\n  '';`;
    expect(await run(privateKeyRule, { 'src/key.ts': concatenated })).toHaveLength(1);
  });

  it('reports a service-account JSON once, at its private_key field', async () => {
    const json = JSON.stringify(
      {
        type: 'service_account',
        project_id: 'demo-proj',
        private_key: fake('pem_pkcs8_escaped', 'k2').replace(/\\n/g, '\n'),
      },
      null,
      2,
    );
    const findings = await run(privateKeyRule, { 'sa.json': json });
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({
      messageId: 'serviceAccount',
      params: { project: 'demo-proj' },
      location: { line: 4 },
    });
  });

  it('labels passphrase-protected keys as lower severity', async () => {
    const enc = fake('pem_rsa', 'k3').replace(
      'RSA PRIVATE KEY-----\n',
      'RSA PRIVATE KEY-----\nProc-Type: 4,ENCRYPTED\nDEK-Info: AES-128-CBC,00\n\n',
    );
    const [f] = await run(privateKeyRule, { id_rsa: enc });
    expect(f).toMatchObject({
      messageId: 'encryptedPemKey',
      severity: 'high',
      confidence: 'medium',
    });
  });
});

describe('secrets/high-entropy', () => {
  it('splits identifiers into words', () => {
    expect(nameWords('apiKeyHeader')).toEqual(['api', 'key', 'header']);
    expect(nameWords('ADMIN_PASSWORD')).toEqual(['admin', 'password']);
    expect(nameWords('JWTSecret')).toEqual(['jwt', 'secret']);
  });

  it.each([
    ['webhookSecret', fake('hex40', 'h1'), 'token'],
    ['JWT_SECRET', fake('b64_48', 'h2'), 'token'],
    ['ADMIN_PASSWORD', fake('password', 'h3'), 'password'],
    ['apiKey', `Bearer ${fake('b64_48', 'h4')}`, 'token'],
  ])('flags %s', (name, value, kind) => {
    expect(classifyCandidate(name, value)?.kind).toBe(kind);
  });

  it.each([
    ['passwordMinLength', '12'],
    ['tokenStorageKey', 'acme-auth-token-v2'],
    ['apiKeyHeader', 'x-api-key'],
    ['sessionTokenCookieName', 'acme_session_2024'],
    ['secretsDocsUrl', 'https://supabase.com/docs/guides/functions/secrets'],
    ['tokenExpired', 'Your session token has expired.'],
    ['buildHash', fake('hex40', 'h5')],
    ['secretId', fake('hex40', 'h6')],
    ['POSTGRES_PASSWORD', 'postgres'],
    ['password', 'password123'],
    ['apiKey', 'test-api-key'],
    ['secret', 'change-me-to-a-long-random-string'],
    ['SUPABASE_ANON_KEY', fake('supabase_anon_jwt', 'h7')],
    ['STRIPE_SECRET_KEY', fake('stripe_live', 'h8')], // provider-key owns it
    ['token', '550e8400-e29b-41d4-a716-446655440000'],
    ['secretKey', '${process.env.SECRET}'],
    ['someName', fake('hex40', 'h9')], // no secret-like name
  ])('does not flag %s = %j', (name, value) => {
    expect(classifyCandidate(name, value)).toBeUndefined();
  });

  it('finds literals in every binding position, and signing keys passed to jwt.sign', async () => {
    const v = (l: string): string => fake('b64_48', l);
    const src = [
      `const apiSecret = '${v('a')}';`,
      `const cfg = { clientSecret: '${v('b')}' };`,
      `cfg.accessToken = '${v('c')}';`,
      `function f(secretKey = '${v('d')}') { return secretKey; }`,
      `const el = <Widget apiKey="${v('e')}" />;`,
      `jwt.sign({ id: 1 }, 'Hunter22!Correct');`,
      `const fromEnv = process.env.API_SECRET ?? '${v('f')}';`,
    ].join('\n');
    const findings = await run(highEntropyRule, { 'src/a.tsx': src });
    expect(findings.map((f) => [f.location.line, f.messageId])).toEqual([
      [1, 'token'],
      [2, 'token'],
      [3, 'token'],
      [4, 'token'],
      [5, 'token'],
      [6, 'signingKey'],
      [7, 'token'],
    ]);
  });

  it('skips human-chosen passwords in tests but keeps random tokens (lower confidence)', async () => {
    const src = `jwt.sign({ id: 1 }, 'test-secret-1');\nconst password = 'Sup3rS3cret!';\nconst apiToken = '${fake('b64_48', 't')}';`;
    const findings = await run(highEntropyRule, { 'test/auth.test.ts': src });
    expect(findings.map((f) => [f.location.line, f.confidence])).toEqual([[3, 'low']]);
  });

  it('reads key/value config files, with low confidence for plain text', async () => {
    const findings = await run(highEntropyRule, {
      'config.json': `{\n  "session": { "secret": "${fake('b64_48', 'j')}" }\n}`,
      'notes.txt': `jwt_secret: ${fake('b64_48', 'k')}`,
    });
    expect(findings.map((f) => [f.location.file, f.confidence])).toEqual([
      ['config.json', 'medium'],
      ['notes.txt', 'low'],
    ]);
  });
});

describe('secrets/env-file-committed', () => {
  const env = `# comment\nEMPTY=\nAPI_URL=https://api.acme.dev\n`;

  it('is critical when git tracks the file', async () => {
    const [f] = await run(envFileCommittedRule, { '.env': env }, ['.env']);
    expect(f).toMatchObject({
      messageId: 'tracked',
      severity: 'critical',
      location: { line: 3 },
      params: { count: 1 },
    });
  });

  it('is medium when untracked but not ignored inside a git repo', async () => {
    const [f] = await run(envFileCommittedRule, { '.env': env, 'a.ts': '' }, ['a.ts']);
    expect(f).toMatchObject({ messageId: 'untracked', severity: 'medium' });
  });

  it('is high/medium confidence without git when not ignored', async () => {
    const [f] = await run(envFileCommittedRule, { '.env.production': env });
    expect(f).toMatchObject({ messageId: 'notIgnored', severity: 'high', confidence: 'medium' });
  });

  it.each([
    ['ignored', { '.gitignore': '.env\n', '.env': env }],
    ['template', { '.env.example': env }],
    ['names only', { '.env': 'A=\nB=your-value-here\n' }],
  ])('does not report %s files', async (_label, files) => {
    expect(await run(envFileCommittedRule, files)).toEqual([]);
  });
});

describe('secrets/client-exposed-env', () => {
  it.each([
    ['SUPABASE_SERVICE_ROLE_KEY', 'secretName'],
    ['STRIPE_SECRET_KEY', 'secretName'],
    ['OPENAI_API_KEY', 'providerName'],
    ['RESEND_API_KEY', 'providerName'],
    ['API_TOKEN', 'mayBeSecret'],
  ])('classifies %s as %s', (bare, id) => {
    expect(classifyExposedName(bare)?.messageId).toBe(id);
  });

  it.each([
    'SUPABASE_URL',
    'SUPABASE_ANON_KEY',
    'SUPABASE_PUBLISHABLE_KEY',
    'STRIPE_PUBLISHABLE_KEY',
    'FIREBASE_API_KEY',
    'GOOGLE_MAPS_API_KEY',
    'RECAPTCHA_SITE_KEY',
    'POSTHOG_KEY',
    'SENTRY_DSN',
    'APP_NAME',
  ])('treats %s as public by design', (bare) => {
    expect(classifyExposedName(bare)).toBeUndefined();
  });

  it('flags a secret value under a public-looking name (service_role pasted into the anon slot)', async () => {
    const [f] = await run(clientExposedEnvRule, {
      '.env.local': `NEXT_PUBLIC_SUPABASE_ANON_KEY=${fake('supabase_service_jwt', 'c1')}\n`,
    });
    expect(f).toMatchObject({
      messageId: 'secretValue',
      severity: 'critical',
      params: { provider: 'Supabase service_role key' },
    });
  });

  it('checks gitignored env files too: the bundler reads them regardless of git', async () => {
    const findings = await run(clientExposedEnvRule, {
      '.gitignore': '.env*\n',
      '.env.local': 'VITE_ADMIN_PASSWORD=Kq83!xLmP2zz\nVITE_FIREBASE_API_KEY=x\n',
    });
    expect(findings.map((f) => f.params['name'])).toEqual(['VITE_ADMIN_PASSWORD']);
  });

  it('lowers confidence for templates and empty values', async () => {
    const [f] = await run(clientExposedEnvRule, {
      '.env.example': 'NEXT_PUBLIC_OPENAI_API_KEY=\n',
    });
    expect(f).toMatchObject({ messageId: 'providerName', confidence: 'medium' });
  });

  it('finds process.env / import.meta.env references, next.config env and vite define', async () => {
    const findings = await run(clientExposedEnvRule, {
      'src/a.tsx': `const k = process.env.NEXT_PUBLIC_OPENAI_API_KEY;\nconst u = process.env.NEXT_PUBLIC_SUPABASE_URL;\nconst p = import.meta.env['VITE_DB_PASSWORD'];`,
      'next.config.mjs': `export default { env: { STRIPE_SECRET_KEY: process.env.STRIPE_SECRET_KEY, APP_VERSION: '1' } };`,
      'vite.config.ts': `export default { define: { 'process.env.OPENAI_API_KEY': '"x"', __APP_VERSION__: '"1"' } };`,
    });
    expect(findings.map((f) => [f.location.file, f.messageId, f.params['name']])).toEqual([
      ['next.config.mjs', 'nextConfigEnv', 'STRIPE_SECRET_KEY'],
      ['src/a.tsx', 'providerName', 'NEXT_PUBLIC_OPENAI_API_KEY'],
      ['src/a.tsx', 'secretName', 'VITE_DB_PASSWORD'],
      ['vite.config.ts', 'viteDefine', 'process.env.OPENAI_API_KEY'],
    ]);
  });
});

describe('parseEnvLines', () => {
  it('handles export, quotes, inline comments and value columns', () => {
    expect(
      parseEnvLines(['export A="x # y"', "B='q'", 'C=plain # note', '# D=1', '  E = spaced']),
    ).toEqual([
      { name: 'A', value: 'x # y', line: 1, column: 8, valueColumn: 11 },
      { name: 'B', value: 'q', line: 2, column: 1, valueColumn: 4 },
      { name: 'C', value: 'plain', line: 3, column: 1, valueColumn: 3 },
      { name: 'E', value: 'spaced', line: 5, column: 3, valueColumn: 7 },
    ]);
  });
});
