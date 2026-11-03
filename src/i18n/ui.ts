import type { DiagnosticCode } from '../core/findings/finding.ts';
import type { Confidence, Severity } from '../core/findings/severity.ts';
import type { Locale } from './locale.ts';

/** Report chrome: everything a reporter prints that is not rule-specific. */
export interface UiStrings {
  readonly reportTitle: string;
  readonly ownCodeNotice: string;
  readonly severity: Readonly<Record<Severity, string>>;
  readonly confidence: Readonly<Record<Confidence, string>>;
  readonly confidenceLabel: string;
  readonly lowConfidenceTag: string;
  readonly summary: string;
  readonly findingsCount: string; // {count}
  readonly noFindings: string;
  /** Shown instead of noFindings when part of the project could not be analysed. */
  readonly noFindingsPartial: string;
  readonly partialCoverage: string;
  readonly filesScanned: string; // {count}, {ms}
  readonly belowThreshold: string; // {count}, {threshold}
  readonly suppressedCount: string; // {count}
  readonly incomplete: string;
  readonly location: string;
  readonly evidence: string;
  readonly rule: string;
  readonly cwe: string;
  readonly remediation: string;
  readonly vulnerable: string;
  readonly fixed: string;
  readonly references: string;
  readonly howToFix: string;
  readonly diagnosticsTitle: string;
  readonly suppressedTitle: string;
  readonly reason: string;
  readonly docs: string;
  readonly diagnostics: Readonly<Record<DiagnosticCode, string>>;
  readonly suppressionProblems: Readonly<
    Record<'missing-reason' | 'reason-too-short' | 'missing-rule-id' | 'unknown-rule-id', string>
  >;
}

const en: UiStrings = {
  reportTitle: 'VibeGuard security report',
  ownCodeNotice: 'Scan only code you own or are authorized to assess.',
  severity: { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' },
  confidence: { high: 'High', medium: 'Medium', low: 'Low' },
  confidenceLabel: 'Confidence',
  lowConfidenceTag: 'low confidence: verify manually',
  summary: 'Summary',
  findingsCount: 'Findings: {count}',
  noFindings: 'No findings.',
  noFindingsPartial:
    'No findings in the parts that could be analysed. Coverage is PARTIAL: see the scan diagnostics before treating this project as clean.',
  partialCoverage:
    'PARTIAL COVERAGE: some files could not be fully analysed (see the scan diagnostics). Findings for affected tables have lowered confidence.',
  filesScanned: 'Files scanned: {count} ({ms} ms)',
  belowThreshold: 'Not shown (below minimum confidence {threshold}): {count}',
  suppressedCount: 'Suppressed by inline comments: {count}',
  incomplete:
    'SCAN INCOMPLETE: one or more rules or files failed. Absence of findings does not mean the code is safe.',
  location: 'Location',
  evidence: 'Evidence',
  rule: 'Rule',
  cwe: 'CWE',
  remediation: 'Remediation',
  vulnerable: 'Vulnerable',
  fixed: 'Fixed',
  references: 'References',
  howToFix: 'How to fix',
  diagnosticsTitle: 'Scan diagnostics',
  suppressedTitle: 'Suppressed findings',
  reason: 'Reason',
  docs: 'Docs',
  diagnostics: {
    'rule-crashed': 'Rule {rule} failed: {error}',
    'file-unreadable': 'File could not be read.',
    'file-too-large': 'File skipped: {size} bytes exceeds the {limit}-byte limit.',
    'parse-failed':
      'SQL statement could not be parsed ({error}); tables it touches are marked unknown.',
    'invalid-suppression': 'Invalid suppression comment ({problem}) {detail}; it has no effect.',
    'unused-suppression': 'Suppression for {rules} matched no finding; remove it.',
    'symlink-skipped': 'Symbolic link not followed.',
    'git-unavailable': 'git is unavailable; committed-file checks fall back to .gitignore rules.',
    'dynamic-sql':
      'A PL/pgSQL block or function body changes tables or policies dynamically ({tables}); VibeGuard does not execute it, so their final Row Level Security state is unknown.',
    'no-migrations':
      'Supabase is used but no SQL migrations were found ({where}). Tables created in the Supabase dashboard are invisible to VibeGuard, so Row Level Security could NOT be checked. Export the schema with `supabase db pull` and commit the migrations.',
  },
  suppressionProblems: {
    'missing-reason': 'a reason after "--" is required',
    'reason-too-short': 'the reason must be at least 10 characters',
    'missing-rule-id': 'a rule id is required',
    'unknown-rule-id': 'unknown rule id',
  },
};

const ar: UiStrings = {
  reportTitle: 'تقرير VibeGuard الأمني',
  ownCodeNotice: 'افحص فقط الشيفرة التي تملكها أو المصرَّح لك بتقييمها.',
  severity: { critical: 'حرجة', high: 'عالية', medium: 'متوسطة', low: 'منخفضة' },
  confidence: { high: 'عالية', medium: 'متوسطة', low: 'منخفضة' },
  confidenceLabel: 'درجة الثقة',
  lowConfidenceTag: 'ثقة منخفضة: تحقَّق يدويًا',
  summary: 'الملخص',
  findingsCount: 'عدد النتائج: {count}',
  noFindings: 'لا توجد نتائج.',
  noFindingsPartial:
    'لا توجد نتائج في الأجزاء التي أمكن تحليلها. التغطية جزئية: راجع تشخيصات الفحص قبل اعتبار هذا المشروع سليمًا.',
  partialCoverage:
    'تغطية جزئية: تعذّر تحليل بعض الملفات تحليلًا كاملًا (راجع تشخيصات الفحص). خُفِّضت درجة الثقة في النتائج المتعلقة بالجداول المتأثرة.',
  filesScanned: 'عدد الملفات المفحوصة: {count} ({ms} ملّي ثانية)',
  belowThreshold: 'نتائج لم تُعرض لأن درجة ثقتها أقل من الحد الأدنى ({threshold}): {count}',
  suppressedCount: 'نتائج مكتومة بتعليقات داخل الشيفرة: {count}',
  incomplete:
    'الفحص غير مكتمل: فشلت قاعدة أو ملف واحد على الأقل. غياب النتائج لا يعني أن الشيفرة آمنة.',
  location: 'الموقع',
  evidence: 'الدليل',
  rule: 'القاعدة',
  cwe: 'CWE',
  remediation: 'المعالجة',
  vulnerable: 'نمط معرَّض للخطر',
  fixed: 'النمط المُصحَّح',
  references: 'مراجع',
  howToFix: 'طريقة الإصلاح',
  diagnosticsTitle: 'تشخيصات الفحص',
  suppressedTitle: 'النتائج المكتومة',
  reason: 'السبب',
  docs: 'التوثيق',
  diagnostics: {
    'rule-crashed': 'فشلت القاعدة {rule}: {error}',
    'file-unreadable': 'تعذّرت قراءة الملف.',
    'file-too-large': 'تم تخطي الملف: حجمه {size} بايت ويتجاوز الحد {limit} بايت.',
    'parse-failed': 'تعذّر تحليل جملة SQL ({error})؛ اعتُبرت الجداول التي تتعلق بها مجهولة الحالة.',
    'invalid-suppression': 'تعليق كتم غير صالح ({problem}) {detail}؛ ليس له أي أثر.',
    'unused-suppression': 'تعليق الكتم الخاص بـ {rules} لم يطابق أي نتيجة؛ احذفه.',
    'symlink-skipped': 'لم يتم تتبّع الرابط الرمزي.',
    'git-unavailable': 'أداة git غير متاحة؛ يُعتمد على قواعد .gitignore بدلًا من ذلك.',
    'dynamic-sql':
      'كتلة PL/pgSQL أو جسم دالة يغيّر الجداول أو السياسات ديناميكيًا ({tables})؛ لا ينفّذها VibeGuard، لذا تبقى الحالة النهائية لـ Row Level Security لهذه الجداول مجهولة.',
    'no-migrations':
      'يستخدم المشروع Supabase لكن لم يُعثر على ملفات ترحيل SQL ({where}). الجداول التي أُنشئت من لوحة تحكم Supabase غير مرئية لـ VibeGuard، لذا لم يكن ممكنًا فحص Row Level Security. صدّر المخطط بالأمر `supabase db pull` وأودِع ملفات الترحيل.',
  },
  suppressionProblems: {
    'missing-reason': 'يجب كتابة سبب بعد "--"',
    'reason-too-short': 'يجب ألا يقل السبب عن 10 أحرف',
    'missing-rule-id': 'يجب تحديد معرّف القاعدة',
    'unknown-rule-id': 'معرّف قاعدة غير معروف',
  },
};

export const UI: Readonly<Record<Locale, UiStrings>> = { en, ar };
