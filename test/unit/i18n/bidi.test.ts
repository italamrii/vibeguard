import { describe, expect, it } from 'vitest';
import { resolveSettings } from '../../../src/core/config/settings.ts';
import { scan } from '../../../src/core/engine/engine.ts';
import {
  findUnisolatedLtr,
  FSI,
  isolateLtrRuns,
  isolateTemplate,
  LRI,
  PDI,
} from '../../../src/i18n/bidi.ts';
import { UI } from '../../../src/i18n/ui.ts';
import { markdownReporter, ruleHelpMarkdown } from '../../../src/reporters/markdown.ts';
import { ALL_RULES } from '../../../src/rules/index.ts';
import { makeProject } from '../../helpers/project.ts';

/** Show isolates as brackets for readable assertions. */
const show = (s: string): string =>
  s.replaceAll(LRI, '[').replaceAll(FSI, '{').replaceAll(PDI, ']');

describe('isolateLtrRuns', () => {
  it.each([
    // The known issue: a leading dot must stay attached to its token.
    ['أضف .env إلى .gitignore الآن', 'أضف [.env] إلى [.gitignore] الآن'],
    ['أودِع ملف .env.example فقط.', 'أودِع ملف [.env.example] فقط.'],
    // Multi-word English names stay one unit; sentence punctuation stays Arabic.
    ['خاصية Row Level Security مفعّلة.', 'خاصية [Row Level Security] مفعّلة.'],
    ['استخدم getUser()، وليس getSession().', 'استخدم [getUser()]، وليس [getSession()].'],
    // Brackets that belong to the Arabic sentence stay outside the isolate.
    ['(المخطط public افتراضيًا)', '(المخطط [public] افتراضيًا)'],
    [
      'الخيار WITH (security_invoker = true) (في Postgres 15)',
      'الخيار [WITH (security_invoker = true)] (في [Postgres 15])',
    ],
    // Code spans and flags.
    ['أضف `.env*` مع --config', 'أضف [`.env*`] مع [--config]'],
    ['حتى 5 محاولات', 'حتى [5] محاولات'],
    // Found by rendering a real report in Chromium: leading colon and an Arabic parenthetical
    // opened inside the run must not be swallowed into one isolate.
    ['عدد الملفات المفحوصة: 171 (47 ملّي ثانية)', 'عدد الملفات المفحوصة: [171] ([47] ملّي ثانية)'],
    ['الحد (5 محاولات كل 15 دقيقة)', 'الحد ([5] محاولات كل [15] دقيقة)'],
  ])('%s', (input, expected) => {
    expect(show(isolateLtrRuns(input))).toBe(expected);
  });

  it('does not touch text already inside isolates, nor pure Arabic', () => {
    const pre = `القاعدة ${LRI}a.b${PDI} هنا`;
    expect(isolateLtrRuns(pre)).toBe(pre);
    expect(isolateLtrRuns('نص عربي فقط، دون أي رموز.')).toBe('نص عربي فقط، دون أي رموز.');
  });

  it('leaves {placeholders} for the caller in templates', () => {
    expect(show(isolateTemplate('المتغير {name} يُضمَّن في JavaScript.'))).toBe(
      'المتغير {name} يُضمَّن في [JavaScript].',
    );
  });
});

describe('findUnisolatedLtr', () => {
  it('flags Latin text outside isolates on Arabic lines, ignoring code fences and LTR-only lines', () => {
    const md = [
      '<div dir="rtl">',
      'ملف .env مكشوف',
      `ملف ${LRI}.env${PDI} آمن`,
      '```ts',
      'const x = "عربي";',
      '```',
      'English only line',
    ].join('\n');
    expect(findUnisolatedLtr(md).map((v) => v.line)).toEqual([2]);
  });
});

describe('Arabic output has no unisolated LTR runs', () => {
  it.each(ALL_RULES.map((r) => [r.meta.id, r] as const))('rule help for %s', (_id, rule) => {
    expect(findUnisolatedLtr(ruleHelpMarkdown(rule.meta, 'ar').join('\n'))).toEqual([]);
  });

  it('every UI string', () => {
    const strings: string[] = [];
    const collect = (v: unknown): void => {
      if (typeof v === 'string') strings.push(v);
      else if (v && typeof v === 'object') Object.values(v).forEach(collect);
    };
    collect(UI.ar);
    // Placeholders are replaced at render time by values the reporters isolate themselves.
    const rendered = strings.map((s) =>
      isolateTemplate(s).replace(/\{[a-zA-Z0-9_]+\}/g, `${LRI}value${PDI}`),
    );
    expect(findUnisolatedLtr(rendered.join('\n'))).toEqual([]);
  });

  it('a full report with suppressions, diagnostics and hostile params', async () => {
    const root = await makeProject({
      'supabase/migrations/1.sql':
        'create table public."Weird Name" (id int);\nalter table t enable row level securty;',
      'src/a.ts':
        "// vibeguard-ignore-next-line secrets/high-entropy -- sample value from the vendor docs\nconst apiSecret = 'k3Pq9xZ2mN7vB4wR8tY1uL6';",
      '.env': 'NEXT_PUBLIC_OPENAI_API_KEY=\n',
    });
    const r = await scan({ root, settings: resolveSettings(undefined), rules: ALL_RULES });
    const md = markdownReporter.render(r, {
      locale: 'ar',
      color: false,
      toolVersion: 't',
      failOn: 'high',
      minConfidence: 'low',
    });
    expect(r.findings.length).toBeGreaterThan(0);
    expect(findUnisolatedLtr(md)).toEqual([]);
  });
});
