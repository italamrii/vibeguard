import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { renderArabicReview, reviewEntries } from '../../helpers/arabic-review.ts';

describe('docs/arabic-review.md', () => {
  it('is up to date (run `npm run arabic-review` after changing any string)', () => {
    const committed = readFileSync(
      new URL('../../../docs/arabic-review.md', import.meta.url),
      'utf8',
    );
    expect(committed).toBe(renderArabicReview());
  });

  it('lists every string with a non-empty Arabic translation that differs from English', () => {
    for (const s of reviewEntries()) {
      for (const e of s.entries) {
        expect(e.ar.trim(), `${s.section} ${e.key}`).not.toBe('');
        // Identical text is allowed only for strings that are pure placeholders/identifiers.
        if (e.ar === e.en)
          expect(
            /[A-Za-z]{4,}/.test(e.en.replace(/\{[^}]+\}/g, '')),
            `${s.section} ${e.key} untranslated`,
          ).toBe(false);
      }
    }
  });
});
