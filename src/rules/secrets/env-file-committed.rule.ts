import path from 'node:path';
import { isEnvTemplateName } from '../../core/discovery/file-kind.ts';
import { defineRule } from '../../core/engine/rule.ts';
import type { FindingInput } from '../../core/findings/finding.ts';
import { scrubText } from '../../core/redaction/redact.ts';
import { SECRETS_REFERENCES } from './common.ts';
import { parseEnvLines } from './env-file.ts';
import { isPlaceholder } from './placeholders.ts';

type Msg = 'tracked' | 'untracked' | 'notIgnored';

export const envFileCommittedRule = defineRule<Msg>({
  meta: {
    id: 'secrets/env-file-committed',
    family: 'secrets',
    defaultSeverity: 'high',
    cwe: [538, 312],
    references: [
      ...SECRETS_REFERENCES,
      'https://nextjs.org/docs/app/guides/environment-variables',
      'https://git-scm.com/docs/gitignore',
    ],
    docs: {
      title: {
        en: 'Environment file with values is committed (or not gitignored)',
        ar: 'ملف متغيرات بيئة يحتوي قيمًا مُودَع في git (أو غير مُستثنى منه)',
      },
      summary: {
        en: '.env files hold the real configuration of an app: database URLs, API keys, signing secrets. When one is tracked by git, every clone, fork and CI cache gets a copy, and it stays in history even after deletion. Adding it to .gitignore afterwards does not untrack it.',
        ar: 'ملفات .env تحمل الإعدادات الحقيقية للتطبيق: روابط قواعد البيانات ومفاتيح API وأسرار التوقيع. عندما يتتبّعها git تحصل كل نسخة وكل fork وكل ذاكرة CI مؤقتة على نسخة منها، وتبقى في السجل حتى بعد حذفها. وإضافتها إلى .gitignore لاحقًا لا تلغي تتبّعها.',
      },
      remediation: {
        text: {
          en: 'Rotate every secret in the file first. Then untrack it (git rm --cached <file>), add `.env*` with `!.env.example` to .gitignore, and commit a .env.example containing names and placeholders only. If the repository was ever pushed, purge the file from history.',
          ar: 'غيّر أولًا كل الأسرار الموجودة في الملف. ثم ألغِ تتبّعه (git rm --cached <file>)، وأضف `.env*` مع `!.env.example` إلى .gitignore، وأودِع ملف .env.example يحتوي الأسماء وقيمًا شكلية فقط. وإن سبق رفع المستودع، فامسح الملف من السجل.',
        },
        codeLanguage: 'bash',
        vulnerable: `# .gitignore
node_modules
.next
# (.env.local is missing, so "git add ." commits it)`,
        fixed: `# .gitignore
node_modules
.next
.env*
!.env.example

# then, once:
git rm --cached .env.local
git commit -m "chore: stop tracking .env.local"`,
      },
    },
    messages: {
      tracked: {
        en: '{file} is tracked by git and contains {count} non-empty value(s).',
        ar: 'الملف {file} يتتبّعه git ويحتوي على {count} من القيم غير الفارغة.',
      },
      untracked: {
        en: '{file} contains {count} value(s) and is not covered by .gitignore; the next "git add ." will commit it.',
        ar: 'الملف {file} يحتوي على {count} من القيم وغير مشمول في .gitignore؛ أمر "git add ." التالي سيُودِعه.',
      },
      notIgnored: {
        en: '{file} contains {count} value(s) and is not covered by .gitignore (no git repository found to confirm whether it is committed).',
        ar: 'الملف {file} يحتوي على {count} من القيم وغير مشمول في .gitignore (لم يُعثر على مستودع git للتأكد مما إذا كان مُودَعًا).',
      },
    },
  },

  async detect(ctx) {
    const out: FindingInput<Msg>[] = [];
    for (const file of ctx.files({ kinds: ['env'] })) {
      const base = path.posix.basename(file.relPath);
      if (isEnvTemplateName(base)) continue;
      let messageId: Msg;
      let severity: 'critical' | 'high' | 'medium';
      let confidence: 'high' | 'medium';
      if (file.gitTracked === true) {
        messageId = 'tracked';
        severity = 'critical';
        confidence = 'high';
      } else if (file.gitIgnored) {
        continue;
      } else if (file.gitTracked === false) {
        messageId = 'untracked';
        severity = 'medium';
        confidence = 'high';
      } else {
        messageId = 'notIgnored';
        severity = 'high';
        confidence = 'medium';
      }

      const t = await ctx.readText(file);
      if (!t) continue;
      const values = parseEnvLines(t.text.split(/\r?\n/)).filter(
        (a) => a.value.length > 0 && !isPlaceholder(a.value),
      );
      const first = values[0];
      if (!first) continue; // names only / placeholders: nothing sensitive to leak
      out.push({
        location: { file: file.relPath, line: first.line, column: 1 },
        messageId,
        params: { file: file.relPath, count: values.length },
        evidence: scrubText(base),
        severity,
        confidence,
        fingerprintKey: messageId,
      });
    }
    return out;
  },
});
