import { defineRule, type Rule } from '../../src/core/engine/rule.ts';
import type { FindingInput } from '../../src/core/findings/finding.ts';
import { scrubText } from '../../src/core/redaction/redact.ts';

const docs = {
  title: { en: 'Test marker', ar: 'علامة اختبار' },
  summary: { en: 'Flags the test marker.', ar: 'يرصد علامة الاختبار.' },
  remediation: {
    text: { en: 'Remove the marker.', ar: 'احذف العلامة.' },
    codeLanguage: 'ts',
    vulnerable: 'const x = "VG_TEST_MARKER";',
    fixed: 'const x = "ok";',
  },
};

/**
 * Engine-level test rule: reports every line containing VG_TEST_MARKER. Confidence and
 * severity can be encoded on the line (`VG_TEST_MARKER:low:critical`) to exercise filters.
 */
export const markerRule: Rule = defineRule({
  meta: {
    id: 'test/marker',
    family: 'test',
    defaultSeverity: 'high',
    cwe: [1],
    references: ['https://example.invalid/ref'],
    docs,
    messages: {
      found: { en: 'Marker found in {name}.', ar: 'تم العثور على العلامة في {name}.' },
    },
  },
  async detect(ctx) {
    const out: FindingInput<'found'>[] = [];
    for (const file of ctx.files()) {
      for await (const { text, line } of ctx.lines(file)) {
        const idx = text.indexOf('VG_TEST_MARKER');
        if (idx === -1) continue;
        const m = /VG_TEST_MARKER(?::(high|medium|low))?(?::(critical|high|medium|low))?/.exec(
          text,
        );
        const confidence = (m?.[1] ?? 'high') as 'high' | 'medium' | 'low';
        const severity = m?.[2] as 'critical' | 'high' | 'medium' | 'low' | undefined;
        out.push({
          location: { file: file.relPath, line, column: idx + 1 },
          messageId: 'found',
          params: { name: file.relPath },
          evidence: scrubText(text.trim()),
          confidence,
          ...(severity ? { severity } : {}),
          fingerprintKey: text.trim(),
        });
      }
    }
    return out;
  },
});

export const crashingRule: Rule = defineRule({
  meta: { ...markerRule.meta, id: 'test/crash', messages: { x: { en: 'x', ar: 'x' } } },
  detect() {
    // Assembled at runtime: the repository must never contain secret-shaped literals (ADR-0007).
    const fakeKey = ['sk', 'live', '51HxQabcdefghijklmnopqrstuv'].join('_');
    return Promise.reject(new Error(`boom with secret ${fakeKey}`));
  },
});

export const badMessageRule: Rule = defineRule({
  meta: { ...markerRule.meta, id: 'test/bad-message', messages: { ok: { en: 'ok', ar: 'ok' } } },
  detect: () =>
    Promise.resolve([
      {
        location: { file: 'a.txt', line: 1, column: 1 },
        messageId: 'nope' as 'ok',
        evidence: scrubText('x'),
        confidence: 'high' as const,
      },
    ]),
});
