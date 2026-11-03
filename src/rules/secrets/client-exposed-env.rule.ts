import path from 'node:path';
import ts from 'typescript';
import { dottedName, staticName, walk } from '../../analysis/ast-utils.ts';
import { CODE_KINDS, isEnvTemplateName } from '../../core/discovery/file-kind.ts';
import { defineRule } from '../../core/engine/rule.ts';
import type { FindingInput } from '../../core/findings/finding.ts';
import type { Confidence, Severity } from '../../core/findings/severity.ts';
import { nodePosition } from '../../core/parsing/ts-parser.ts';
import { redactSecret, scrubText } from '../../core/redaction/redact.ts';
import { confidenceForPath, SECRETS_REFERENCES } from './common.ts';
import { parseEnvLines } from './env-file.ts';
import { findSecrets } from './patterns.ts';
import { isPlaceholder } from './placeholders.ts';

type Msg =
  'secretName' | 'providerName' | 'mayBeSecret' | 'secretValue' | 'nextConfigEnv' | 'viteDefine';

/**
 * Prefixes that make a bundler inline the variable into client JavaScript. Longest first.
 * Next.js, Vite, Create React App, Expo, Nuxt, SvelteKit/Astro, Gatsby, Vue CLI.
 */
export const PUBLIC_ENV_PREFIXES = [
  'NEXT_PUBLIC_',
  'NUXT_PUBLIC_',
  'EXPO_PUBLIC_',
  'REACT_APP_',
  'VUE_APP_',
  'GATSBY_',
  'PUBLIC_',
  'VITE_',
] as const;

export function publicPrefixOf(name: string): string | undefined {
  return PUBLIC_ENV_PREFIXES.find((p) => name.startsWith(p));
}

const CRITICAL_NAME =
  /SERVICE[_-]?ROLE|SECRET|PRIVATE[_-]?KEY|PASSWORD|PASSWD|DB[_-]?PASS|DATABASE[_-]?URL|CONNECTION[_-]?STRING|MASTER[_-]?KEY|ADMIN[_-]?(?:KEY|TOKEN)/i;
/** Values that are meant to be public (protected by RLS, Security Rules, origin restrictions, …). */
const PUBLIC_BY_DESIGN =
  /ANON[_-]?KEY|PUBLISHABLE|PUBLIC[_-]?KEY|_URL$|^URL$|_URI$|_DSN$|SITE[_-]?KEY|MEASUREMENT[_-]?ID|APP[_-]?ID$|PROJECT[_-]?ID|AUTH[_-]?DOMAIN|STORAGE[_-]?BUCKET|MESSAGING[_-]?SENDER|FIREBASE[_-]?(?:WEB[_-]?)?API[_-]?KEY|MAPS?[_-]|MAPBOX|POSTHOG|SEGMENT|MIXPANEL|AMPLITUDE|ALGOLIA[_-]?(?:SEARCH|APP)|VAPID[_-]?PUBLIC|^GA[_-]|^GTM[_-]|SENTRY|PLAUSIBLE|UMAMI|RECAPTCHA|TURNSTILE|HCAPTCHA|CLERK[_-]?PUBLISHABLE/i;
const SECRET_PROVIDER =
  /OPENAI|ANTHROPIC|CLAUDE|GROQ|MISTRAL|COHERE|REPLICATE|HUGGING|^HF[_-]|DEEPSEEK|PERPLEXITY|ELEVENLABS|PINECONE|RESEND|SENDGRID|MAILGUN|POSTMARK|TWILIO|GITHUB|AWS|STRIPE|SUPABASE|FIREBASE[_-]?ADMIN|SLACK|DISCORD|TELEGRAM|GEMINI|GOOGLE[_-]?AI|UPSTASH/i;
const KEYISH = /KEY|TOKEN|AUTH|CREDENTIAL/i;

export interface NameVerdict {
  readonly messageId: 'secretName' | 'providerName' | 'mayBeSecret';
  readonly severity: Severity;
  readonly confidence: Confidence;
}

/** Classify the part of an exposed variable name after its public prefix. Exported for tests. */
export function classifyExposedName(bare: string): NameVerdict | undefined {
  if (CRITICAL_NAME.test(bare))
    return { messageId: 'secretName', severity: 'critical', confidence: 'high' };
  if (PUBLIC_BY_DESIGN.test(bare)) return undefined;
  if (SECRET_PROVIDER.test(bare) && KEYISH.test(bare)) {
    return { messageId: 'providerName', severity: 'critical', confidence: 'high' };
  }
  if (KEYISH.test(bare)) return { messageId: 'mayBeSecret', severity: 'high', confidence: 'low' };
  return undefined;
}

const NEXT_CONFIG = /(?:^|\/)next\.config\.(?:js|mjs|cjs|ts|mts)$/;
const VITE_CONFIG = /(?:^|\/)vite\.config\.(?:js|mjs|cjs|ts|mts)$/;

export const clientExposedEnvRule = defineRule<Msg>({
  meta: {
    id: 'secrets/client-exposed-env',
    family: 'secrets',
    defaultSeverity: 'critical',
    cwe: [200, 312],
    references: [
      'https://nextjs.org/docs/app/guides/environment-variables#bundling-environment-variables-for-the-browser',
      'https://vite.dev/guide/env-and-mode',
      'https://supabase.com/docs/guides/api/api-keys',
      ...SECRETS_REFERENCES,
    ],
    docs: {
      title: {
        en: 'Secret exposed to the browser through a public env variable',
        ar: 'سرّ مكشوف للمتصفح عبر متغير بيئة عام',
      },
      summary: {
        en: 'Variables prefixed NEXT_PUBLIC_, VITE_, REACT_APP_, EXPO_PUBLIC_ (and similar), every key in next.config `env`, and Vite `define` entries are copied as plain text into the JavaScript sent to every visitor. Anything secret placed there (a service_role key, an OpenAI key, a Stripe secret key) is public, no matter how the variable is named or where the .env file lives.',
        ar: 'المتغيرات التي تبدأ بالبادئات NEXT_PUBLIC_ أو VITE_ أو REACT_APP_ أو EXPO_PUBLIC_ (وما شابهها)، وكل مفتاح في `env` ضمن next.config، وإدخالات `define` في Vite، تُنسخ كنص صريح داخل شيفرة JavaScript التي تُرسل إلى كل زائر. أي سرّ يوضع فيها (مفتاح service_role أو مفتاح OpenAI أو مفتاح Stripe السري) يصبح علنيًا مهما كان اسم المتغير أو مكان ملف .env.',
      },
      remediation: {
        text: {
          en: 'Rotate the secret. Remove the public prefix and only read the variable in server code (route handlers, server actions, API routes, edge functions). The browser calls your server, and your server calls the provider. For Supabase, the browser gets only the anon/publishable key, and Row Level Security protects data.',
          ar: 'غيّر السرّ. أزل البادئة العامة واقرأ المتغير في شيفرة الخادم فقط (route handlers أو server actions أو API routes أو edge functions). يتصل المتصفح بخادمك، وخادمك يتصل بالمزوّد. في Supabase لا يحصل المتصفح إلا على المفتاح anon/publishable، وسياسات Row Level Security هي ما يحمي البيانات.',
        },
        codeLanguage: 'ts',
        vulnerable: `// .env.local
NEXT_PUBLIC_OPENAI_API_KEY=sk-proj-…

// app/chat/page.tsx ('use client')
const res = await fetch('https://api.openai.com/v1/chat/completions', {
  headers: { Authorization: \`Bearer \${process.env.NEXT_PUBLIC_OPENAI_API_KEY}\` },
});`,
        fixed: `// .env.local
OPENAI_API_KEY=sk-proj-…   # no NEXT_PUBLIC_ prefix

// app/api/chat/route.ts (server)
export async function POST(req: Request) {
  const user = await requireUser(); // authenticate before spending your quota
  const res = await fetch('https://api.openai.com/v1/chat/completions', {
    method: 'POST',
    headers: { Authorization: \`Bearer \${process.env.OPENAI_API_KEY}\` },
    body: JSON.stringify(await buildPrompt(req, user)),
  });
  return new Response(res.body);
}

// app/chat/page.tsx ('use client')
await fetch('/api/chat', { method: 'POST', body: JSON.stringify({ message }) });`,
      },
    },
    messages: {
      secretName: {
        en: '{name} is inlined into client JavaScript, and its name says it is a secret.',
        ar: 'المتغير {name} يُضمَّن في شيفرة JavaScript الخاصة بالمتصفح، واسمه يدل على أنه سرّ.',
      },
      providerName: {
        en: '{name} is inlined into client JavaScript and looks like a server-side API credential.',
        ar: 'المتغير {name} يُضمَّن في شيفرة JavaScript الخاصة بالمتصفح ويبدو بيانات اعتماد API مخصّصة للخادم.',
      },
      mayBeSecret: {
        en: '{name} is inlined into client JavaScript and may be a credential. Confirm it is meant to be public.',
        ar: 'المتغير {name} يُضمَّن في شيفرة JavaScript الخاصة بالمتصفح وقد يكون بيانات اعتماد. تأكّد من أنه مقصود أن يكون عامًا.',
      },
      secretValue: {
        en: '{name} is inlined into client JavaScript and its value is a {provider}.',
        ar: 'المتغير {name} يُضمَّن في شيفرة JavaScript الخاصة بالمتصفح وقيمته من نوع {provider}.',
      },
      nextConfigEnv: {
        en: 'next.config `env.{name}` is inlined into client JavaScript, and the name suggests a secret.',
        ar: 'المفتاح `env.{name}` في next.config يُضمَّن في شيفرة JavaScript الخاصة بالمتصفح، واسمه يوحي بأنه سرّ.',
      },
      viteDefine: {
        en: 'Vite `define` replaces {name} with its value in client JavaScript, and the name suggests a secret.',
        ar: 'خيار `define` في Vite يستبدل {name} بقيمته داخل شيفرة JavaScript الخاصة بالمتصفح، واسمه يوحي بأنه سرّ.',
      },
    },
  },

  async detect(ctx) {
    const out: FindingInput<Msg>[] = [];

    // 1. .env files: every file, including gitignored ones. The bundler reads them at build
    //    time and ships the values to the browser whether or not git ever sees them.
    for (const file of ctx.files({ kinds: ['env'] })) {
      const t = await ctx.readText(file);
      if (!t) continue;
      const template = isEnvTemplateName(path.posix.basename(file.relPath));
      for (const a of parseEnvLines(t.text.split(/\r?\n/))) {
        const prefix = publicPrefixOf(a.name);
        if (prefix === undefined) continue;
        const hasValue = a.value.length > 0 && !isPlaceholder(a.value);
        // Match on the whole assignment so context checks (e.g. "FIREBASE" in the name) apply.
        const valueSecret = hasValue ? findSecrets(`${a.name}=${a.value}`)[0] : undefined;
        if (valueSecret) {
          out.push({
            location: { file: file.relPath, line: a.line, column: a.column },
            messageId: 'secretValue',
            params: { name: a.name, provider: valueSecret.provider },
            evidence: redactSecret(a.value),
            severity: 'critical',
            confidence: 'high',
            fingerprintKey: `env:${a.name}`,
          });
          continue;
        }
        const v = classifyExposedName(a.name.slice(prefix.length));
        if (!v) continue;
        // A template or an empty value tells us the app expects it public, not that it leaked yet.
        const confidence: Confidence =
          template || !hasValue ? (v.confidence === 'high' ? 'medium' : 'low') : v.confidence;
        out.push({
          location: { file: file.relPath, line: a.line, column: a.column },
          messageId: v.messageId,
          params: { name: a.name },
          evidence: hasValue ? redactSecret(a.value) : scrubText(a.name),
          severity: v.severity,
          confidence,
          fingerprintKey: `env:${a.name}`,
        });
      }
    }

    // 2. Code: process.env.X / import.meta.env.X references, next.config env, vite define.
    for (const file of ctx.files({ kinds: CODE_KINDS })) {
      const t = await ctx.readText(file);
      if (!t || !/env|define/.test(t.text)) continue;
      const parsed = await ctx.parseTs(file);
      if (!parsed) continue;
      const sf = parsed.sourceFile;
      const isNextConfig = NEXT_CONFIG.test(file.relPath);
      const isViteConfig = VITE_CONFIG.test(file.relPath);

      walk(sf, (node) => {
        if (ts.isPropertyAccessExpression(node) || ts.isElementAccessExpression(node)) {
          const full = dottedName(node);
          const m =
            full === undefined
              ? null
              : /^(?:process\.env|import\.meta\.env)\.([A-Za-z_][A-Za-z0-9_]*)$/.exec(full);
          const name = m?.[1];
          if (name !== undefined) {
            const prefix = publicPrefixOf(name);
            const v =
              prefix === undefined ? undefined : classifyExposedName(name.slice(prefix.length));
            if (v)
              out.push(
                codeFinding(file.relPath, sf, node, v.messageId, name, v.severity, v.confidence),
              );
            return false;
          }
        }
        if ((isNextConfig || isViteConfig) && ts.isPropertyAssignment(node)) {
          const key = staticName(node.name);
          if (isNextConfig && key === 'env' && ts.isObjectLiteralExpression(node.initializer)) {
            for (const p of node.initializer.properties) {
              const name = staticName(p.name);
              const v = name === undefined ? undefined : classifyExposedName(name);
              if (name !== undefined && v) {
                out.push(
                  codeFinding(
                    file.relPath,
                    sf,
                    p,
                    'nextConfigEnv',
                    name,
                    v.severity,
                    lower(v.confidence),
                  ),
                );
              }
            }
          }
          if (isViteConfig && key === 'define' && ts.isObjectLiteralExpression(node.initializer)) {
            for (const p of node.initializer.properties) {
              const raw = staticName(p.name);
              const name = raw
                ?.split('.')
                .pop()
                ?.replace(/^_+|_+$/g, '');
              const v = name
                ? classifyExposedName(
                    publicPrefixOf(name) ? name.slice((publicPrefixOf(name) ?? '').length) : name,
                  )
                : undefined;
              if (raw !== undefined && v) {
                out.push(
                  codeFinding(
                    file.relPath,
                    sf,
                    p,
                    'viteDefine',
                    raw,
                    v.severity,
                    lower(v.confidence),
                  ),
                );
              }
            }
          }
        }
        return undefined;
      });
    }
    return out;
  },
});

/** Config-object entries: the value might be a non-secret despite the name; one step less sure. */
function lower(c: Confidence): Confidence {
  return c === 'high' ? 'medium' : 'low';
}

function codeFinding(
  file: string,
  sf: ts.SourceFile,
  node: ts.Node,
  messageId: Msg,
  name: string,
  severity: Severity,
  confidence: Confidence,
): FindingInput<Msg> {
  const pos = nodePosition(sf, node);
  return {
    location: {
      file,
      line: pos.line,
      column: pos.column,
      endLine: pos.endLine,
      endColumn: pos.endColumn,
    },
    messageId,
    params: { name },
    evidence: scrubText(node.getText(sf), { maxLength: 120 }),
    severity,
    confidence: confidenceForPath(confidence, file),
    fingerprintKey: `${messageId}:${name}`,
  };
}
