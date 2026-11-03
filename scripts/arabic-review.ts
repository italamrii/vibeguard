/** Regenerate docs/arabic-review.md (every Arabic string next to its English source). */
import { writeFile } from 'node:fs/promises';
import { renderArabicReview } from '../test/helpers/arabic-review.ts';

const target = new URL('../docs/arabic-review.md', import.meta.url);
await writeFile(target, renderArabicReview());
console.log(`Wrote ${target.pathname}`);
