import ts from 'typescript';
import { calleeName, staticName, stringValue, walk } from '../../analysis/ast-utils.ts';
import { CODE_KINDS } from '../../core/discovery/file-kind.ts';
import { defineRule } from '../../core/engine/rule.ts';
import type { FindingInput } from '../../core/findings/finding.ts';
import type { Confidence, Severity } from '../../core/findings/severity.ts';
import { nodePosition } from '../../core/parsing/ts-parser.ts';
import { scrubText } from '../../core/redaction/redact.ts';

type Msg = 'reflectedOrigin' | 'wildcardWithCredentials';

const ACAO = /^access-control-allow-origin$/i;
const ACAC = /^access-control-allow-credentials$/i;
/** A file that checks the origin against a list before echoing it is doing it right. */
const ALLOWLIST =
  /allow(?:ed)?_?(?:list|origins?)|whitelist|\.includes\(\s*(?:req\.headers\.origin|origin)|\.has\(\s*origin|origin\s*===\s*['"`]|\.test\(\s*origin/i;

type OriginKind = 'wildcard' | 'reflect' | 'fixed';

/** Classify the value given for the allowed origin. */
function originKind(n: ts.Node | undefined): OriginKind {
  if (!n) return 'wildcard'; // cors({ credentials: true }) defaults origin to '*'
  const s = stringValue(n);
  if (s !== undefined) return s === '*' ? 'wildcard' : 'fixed';
  if (n.kind === ts.SyntaxKind.TrueKeyword) return 'reflect'; // cors: origin: true reflects the request origin
  if (ts.isArrayLiteralExpression(n) || ts.isRegularExpressionLiteral(n)) return 'fixed';
  // origin: (origin, cb) => cb(null, true): allows every origin
  if (ts.isArrowFunction(n) || ts.isFunctionExpression(n)) {
    const body = n.body.getText();
    return /\(\s*null\s*,\s*true\s*\)|return\s+true|\(\s*null\s*,\s*origin\s*\)/.test(body) &&
      !ALLOWLIST.test(body)
      ? 'reflect'
      : 'fixed';
  }
  return /origin/i.test(n.getText()) ? 'reflect' : 'fixed';
}

function isTrue(n: ts.Node | undefined): boolean {
  return n !== undefined && (n.kind === ts.SyntaxKind.TrueKeyword || stringValue(n) === 'true');
}

export const corsWildcardCredentialsRule = defineRule<Msg>({
  meta: {
    id: 'endpoints/cors-wildcard-credentials',
    family: 'endpoints',
    defaultSeverity: 'high',
    cwe: [942, 346],
    references: [
      'https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/CORS#requests_with_credentials',
      'https://portswigger.net/web-security/cors',
      'https://github.com/expressjs/cors#configuration-options',
    ],
    docs: {
      title: {
        en: 'CORS allows any origin together with credentials',
        ar: 'إعدادات CORS تسمح بأي مصدر مع إرسال بيانات الاعتماد',
      },
      summary: {
        en: 'With Access-Control-Allow-Credentials: true, browsers send the user\'s cookies on cross-site requests. If the server also echoes back whatever Origin the request had (cors({ origin: true }), a callback that always allows, or res.setHeader(\'Access-Control-Allow-Origin\', req.headers.origin)), any website the user visits can call your API as them and read the responses. A literal "*" with credentials is rejected by browsers, but it shows the intent, and the usual "fix" is reflection.',
        ar: 'عند ضبط Access-Control-Allow-Credentials: true يرسل المتصفح ملفات تعريف الارتباط الخاصة بالمستخدم مع الطلبات القادمة من مواقع أخرى. وإن كان الخادم يعيد أيضًا أي قيمة Origin جاءت في الطلب (cors({ origin: true }) أو دالة تسمح دائمًا أو res.setHeader(\'Access-Control-Allow-Origin\', req.headers.origin))، فإن أي موقع يزوره المستخدم يستطيع استدعاء واجهتك باسمه وقراءة الاستجابات. أما "*" الحرفية مع بيانات الاعتماد فيرفضها المتصفح، لكنها تكشف النية، و"الحلّ" المعتاد لها هو إعادة الـ Origin كما هو.',
      },
      remediation: {
        text: {
          en: 'Allow an explicit list of trusted origins. Only set credentials: true when cookies must cross origins. Never echo the request Origin without checking it against the list.',
          ar: 'اسمح بقائمة صريحة من المصادر الموثوقة. ولا تضبط credentials: true إلا إذا كان لا بد من إرسال ملفات تعريف الارتباط بين مصادر مختلفة. ولا تُعد قيمة Origin الواردة في الطلب دون مقارنتها بالقائمة.',
        },
        codeLanguage: 'ts',
        vulnerable: `app.use(cors({ origin: true, credentials: true }));`,
        fixed: `const allowedOrigins = ['https://app.example.com', 'https://admin.example.com'];
app.use(cors({
  origin: (origin, cb) => cb(null, !origin || allowedOrigins.includes(origin)),
  credentials: true,
}));`,
      },
    },
    messages: {
      reflectedOrigin: {
        en: 'CORS echoes any request origin and allows credentials: any website can make authenticated requests as your users and read the responses.',
        ar: 'إعدادات CORS تعيد أي مصدر وارد في الطلب وتسمح ببيانات الاعتماد: يستطيع أي موقع إرسال طلبات موثّقة باسم مستخدميك وقراءة الاستجابات.',
      },
      wildcardWithCredentials: {
        en: 'CORS combines Access-Control-Allow-Origin "*" with credentials. Browsers reject this combination, so cross-origin calls fail. Use an explicit origin list, not reflection.',
        ar: 'إعدادات CORS تجمع بين Access-Control-Allow-Origin "*" وبيانات الاعتماد. يرفض المتصفح هذا الجمع فتفشل الطلبات بين المصادر. استخدم قائمة مصادر صريحة، لا إعادة الـ Origin كما هو.',
      },
    },
  },

  async detect(ctx) {
    const out: FindingInput<Msg>[] = [];
    for (const file of ctx.files({ kinds: CODE_KINDS })) {
      const t = await ctx.readText(file);
      if (!t || !/cors|access-control-allow/i.test(t.text)) continue;
      const parsed = await ctx.parseTs(file);
      if (!parsed) continue;
      const sf = parsed.sourceFile;
      const allowlisted = ALLOWLIST.test(t.text);
      const report = (node: ts.Node, kind: OriginKind): void => {
        if (kind === 'fixed' || (kind === 'reflect' && allowlisted)) return;
        const pos = nodePosition(sf, node);
        const [messageId, severity, confidence]: [Msg, Severity, Confidence] =
          kind === 'reflect'
            ? ['reflectedOrigin', 'high', 'high']
            : ['wildcardWithCredentials', 'medium', 'high'];
        out.push({
          location: { file: file.relPath, line: pos.line, column: pos.column },
          messageId,
          params: {},
          evidence: scrubText(node.getText(sf).replace(/\s+/g, ' '), { maxLength: 120 }),
          severity,
          confidence,
          fingerprintKey: `${messageId}:${pos.line}`,
        });
      };

      // 1. cors({ … }) / fastify.register(cors, { … })
      walk(sf, (n) => {
        if (!ts.isCallExpression(n)) return undefined;
        const name = calleeName(n) ?? '';
        const opts = /(?:^|\.)cors$/i.test(name)
          ? n.arguments[0]
          : /(?:^|\.)register$/.test(name) && /cors/i.test(n.arguments[0]?.getText(sf) ?? '')
            ? n.arguments[1]
            : undefined;
        if (!opts || !ts.isObjectLiteralExpression(opts)) return undefined;
        const props = new Map(
          opts.properties.flatMap((p) =>
            ts.isPropertyAssignment(p) ? [[staticName(p.name) ?? '', p.initializer] as const] : [],
          ),
        );
        if (!isTrue(props.get('credentials'))) return undefined;
        report(n, originKind(props.get('origin')));
        return undefined;
      });

      // 2. Manual headers: setHeader/header/set/append('Access-Control-…', v), header objects,
      //    and next.config headers() entries { key: 'Access-Control-…', value: v }.
      const origins: { node: ts.Node; kind: OriginKind }[] = [];
      // Mutated inside the walk callback; an object keeps control-flow narrowing honest.
      const seen = { credentials: false };
      walk(sf, (n) => {
        if (ts.isCallExpression(n) && n.arguments.length >= 2) {
          const key = stringValue(n.arguments[0] as ts.Node);
          const name = (calleeName(n) ?? '').split('.').pop() ?? '';
          if (key && /^(?:setHeader|header|set|append)$/.test(name)) {
            if (ACAO.test(key)) origins.push({ node: n, kind: originKind(n.arguments[1]) });
            if (ACAC.test(key) && isTrue(n.arguments[1])) seen.credentials = true;
          }
        }
        if (ts.isObjectLiteralExpression(n)) {
          const props = n.properties.filter(ts.isPropertyAssignment);
          const keyProp = props.find((p) => staticName(p.name) === 'key');
          const valueProp = props.find((p) => staticName(p.name) === 'value');
          const key = keyProp ? stringValue(keyProp.initializer) : undefined;
          if (key && valueProp) {
            if (ACAO.test(key)) origins.push({ node: n, kind: originKind(valueProp.initializer) });
            if (ACAC.test(key) && isTrue(valueProp.initializer)) seen.credentials = true;
          }
          for (const p of props) {
            const k = staticName(p.name) ?? '';
            if (ACAO.test(k)) origins.push({ node: p, kind: originKind(p.initializer) });
            if (ACAC.test(k) && isTrue(p.initializer)) seen.credentials = true;
          }
        }
        return undefined;
      });
      if (seen.credentials) for (const o of origins) report(o.node, o.kind);
    }
    return out;
  },
});
