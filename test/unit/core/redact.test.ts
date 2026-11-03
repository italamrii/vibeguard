import { describe, expect, it } from 'vitest';
import { redactSecret, scrubText, shannonEntropy } from '../../../src/core/redaction/redact.ts';

// Secret-shaped values are assembled at runtime (ADR-0007).
const j = (...parts: string[]): string => parts.join('');

describe('redactSecret', () => {
  it('shows the first 4 characters and the length', () => {
    expect(redactSecret('abcdefghijklmnop')).toBe('abcd…[16 chars]');
  });

  it('shows only the length for short values', () => {
    expect(redactSecret('abcdefgh')).toBe('…[8 chars]');
    expect(redactSecret('')).toBe('…[0 chars]');
  });

  it('counts code points, not UTF-16 units', () => {
    expect(redactSecret('🔑🔑🔑🔑🔑🔑🔑🔑🔑🔑')).toBe('🔑🔑🔑🔑…[10 chars]');
  });

  it('never contains more than 4 characters of the input', () => {
    const secret = j('ghp_', 'A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8');
    const r = redactSecret(secret);
    expect(r).not.toContain(secret.slice(0, 5));
  });
});

describe('scrubText', () => {
  it('redacts known secrets verbatim', () => {
    const s = 'const k = "hunter2hunter2";';
    expect(scrubText(s, { knownSecrets: ['hunter2hunter2'] })).toBe('const k = "hunt…[14 chars]";');
  });

  it('redacts JWT-shaped strings', () => {
    const jwt = j(
      'eyJhbGciOiJIUzI1NiJ9',
      '.',
      'eyJyb2xlIjoic2VydmljZV9yb2xlIn0',
      '.',
      'c2lnbmF0dXJlLXNpZ25hdHVyZQ',
    );
    const out = scrubText(`key: "${jwt}"`);
    expect(out).not.toContain(jwt);
    expect(out).toContain('eyJh…[');
  });

  it('redacts URL passwords but keeps the rest of the URL', () => {
    const out = scrubText(j('postgres://app:', 'S3cr3tPassw0rd', '@db.example.com:5432/app'));
    expect(out).toBe('postgres://app:S3cr…[14 chars]@db.example.com:5432/app');
  });

  it('redacts PEM private key blocks', () => {
    const pem = j(
      '-----BEGIN ',
      'PRIVATE KEY-----\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASC\n-----END ',
      'PRIVATE KEY-----',
    );
    expect(scrubText(pem)).not.toContain('MIIEvQIBADANBgkqhkiG9w0BAQEFAASC');
  });

  it('redacts high-entropy tokens', () => {
    const tok = j('xK9mQ2vL8pR4', 'tN7wE3yU6iO1aS5d');
    expect(scrubText(`token=${tok}`)).not.toContain(tok);
  });

  it('leaves ordinary code alone', () => {
    const s = "import { createClient } from '@supabase/supabase-js/dist/module/index.js';";
    expect(scrubText(s)).toBe(s);
    expect(scrubText('const supabaseServiceRoleKeyName = process.env.SUPABASE_URL;')).toBe(
      'const supabaseServiceRoleKeyName = process.env.SUPABASE_URL;',
    );
  });

  it('truncates long text', () => {
    expect(Array.from(scrubText('a '.repeat(500), { maxLength: 50 }))).toHaveLength(50);
  });

  it('is linear on adversarial input (ReDoS guard)', () => {
    const inputs = [
      'a'.repeat(100_000),
      'eyJ'.repeat(30_000),
      'x://'.repeat(25_000) + ':',
      '-----BEGIN PRIVATE KEY-----' + 'A'.repeat(100_000),
    ];
    for (const input of inputs) {
      const t0 = performance.now();
      scrubText(input);
      expect(performance.now() - t0).toBeLessThan(500);
    }
  });
});

describe('shannonEntropy', () => {
  it('is 0 for a repeated character and log2(n) for n distinct', () => {
    expect(shannonEntropy('aaaa')).toBe(0);
    expect(shannonEntropy('abcd')).toBeCloseTo(2);
  });
});
