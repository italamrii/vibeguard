# Contributing to VibeGuard

Thanks for helping. VibeGuard is a security tool, so the bar for correctness is high. A
false positive is a bug, and a crash must never turn into a silent pass.

## Requirements

| Tool | Version                           | Notes                                                                                                                                                                                                                                                                                       |
| ---- | --------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Node | **≥ 20.19**                       | CI runs Node 20 and 22.                                                                                                                                                                                                                                                                     |
| npm  | **≥ 11** to _change_ dependencies | npm 10.9 crashes (`Cannot read properties of null (reading 'edgesOut')`) when it resolves vitest's optional peer dependencies. Use `npx npm@11 install <pkg>` to add or update a dependency. `npm ci` from the committed lockfile works on npm 10, so plain installs and CI are unaffected. |
| git  | any recent                        | Tests create throwaway git repositories to exercise committed-file detection.                                                                                                                                                                                                               |

Scripts in `scripts/` are TypeScript and run through [`tsx`](https://tsx.is), so they work
on Node 20. (Node ≥ 22.18 can also run them directly with `node scripts/x.ts`, but don't
depend on that.)

## Everyday commands

```bash
npm ci
```

```bash
npm run lint        # ESLint + Prettier check
```

```bash
npm run typecheck
```

```bash
npm test            # Vitest: unit + integration + fixture accuracy
```

```bash
npm run build       # tsc → dist/
```

```bash
npm run bench       # synthetic 5k-file performance run
```

Release and documentation gates (all run in CI):

```bash
npm run accuracy -- --check     # fixture precision/recall; fails on any FP or unexpected miss
```

```bash
npm run docs:rules -- --check   # docs/rules pages are current and hand sections are written
```

```bash
npm run licenses:check -- --check   # dependency license policy + docs/dependencies.md
```

```bash
npm run pack:check              # npm tarball contains only the allowlist, nothing secret-shaped
```

```bash
npm run sarif:check             # SARIF validates against the OASIS schema and GitHub's limits
```

## Ground rules

- **Never commit a secret-shaped string**, not even a fake one. GitHub push protection and
  secret scanning would flag it, and so would every other scanner pointed at this repo.
  Tests and fixtures assemble fake values at runtime (`test/helpers/fake-secrets.ts`, see
  ADR-0007). Write `['sk', 'live', body].join('_')`, never the literal.
- **No invisible bidi characters in source.** A test enforces this. Spell them as `\u` escapes.
- **Every rule ships in English and Arabic.** The type system enforces this. If you are not
  confident in the Arabic, say so in the PR so a native speaker can review it.
- **Every new detection needs a positive and a negative test**, including realistic
  look-alikes (documentation examples, placeholders, test-mode keys).
- **Fixture changes must keep the clean apps at zero findings.** Run `npm test` and check
  `docs/accuracy.md` (`npm run accuracy`).
- Commits follow [Conventional Commits](https://www.conventionalcommits.org/) and stay
  small and focused.
- Significant design decisions get an ADR in `docs/adr/`.

## Writing a rule

VibeGuard v1 has exactly three rule families: `secrets`, `supabase` and `endpoints`. New
rules must fit one of them. A new family needs an issue and an ADR first.

### 1. Fixtures first

Write the expected behaviour down **before** the detector, in a separate commit:

- Add the vulnerable case to a `fixtures/*-vuln` app, with the annotation on the line
  above the line the finding should point to:

  ```ts
  // vg-expect: endpoints/my-new-rule
  export async function POST(req: Request) {
  ```

  A known false negative you accept for now is annotated
  `vg-expect-miss: <rule-id> -- <why it is missed>`, and is listed in [docs/threat-model.md](docs/threat-model.md).

- Add the safe look-alike to the matching `fixtures/*-clean` app. Clean apps must stay at
  **zero findings**.
- Secret-shaped values in fixtures are template placeholders (`{{FAKE:kind:label}}`),
  assembled at build time by `scripts/build-fixtures.ts` ([ADR-0007](docs/adr/0007-fixture-templates.md)).
  Files that must be dotfiles in the built app are named `dot_…` in the template.

Commit this first (`test(fixtures): …`). `npm run accuracy` will now report the new
expectation as a miss, which is the point.

### 2. The rule

A rule is one file, `src/rules/<family>/<name>.rule.ts`, built with `defineRule`:

```ts
import { defineRule } from '../../core/engine/rule.ts';
import type { FindingInput } from '../../core/findings/finding.ts';
import { redactSecret } from '../../core/redaction/redact.ts';

type Msg = 'example';

export const myNewRule = defineRule<Msg>({
  meta: {
    id: 'endpoints/my-new-rule', // stable: users put it in config and suppressions
    family: 'endpoints',
    defaultSeverity: 'high',
    cwe: [306], // most specific first; add a name in scripts/lib/rule-docs.ts if new
    references: ['https://cwe.mitre.org/data/definitions/306.html'],
    docs: {
      title: { en: '…', ar: '…' },
      summary: { en: 'Why it matters…', ar: '…' },
      remediation: {
        text: { en: 'How to fix…', ar: '…' },
        codeLanguage: 'ts',
        vulnerable: `// the unsafe pattern`,
        fixed: `// the safe pattern`,
      },
    },
    messages: {
      example: { en: '{endpoint} does something unsafe.', ar: '…' },
    },
  },
  async detect(ctx) {
    const out: FindingInput<Msg>[] = [];
    for (const file of ctx.files({ kinds: ['ts', 'tsx', 'js', 'jsx'] })) {
      const parsed = await ctx.parseTs(file); // lazy, cached, parse-only
      if (!parsed) continue;
      // … find the pattern …
      out.push({
        location: { file: file.relPath, line: 1, column: 1 },
        messageId: 'example',
        params: { endpoint: 'POST /api/x' },
        evidence: redactSecret('…'), // evidence must be Redacted: never a raw secret
        confidence: 'medium',
      });
    }
    return out;
  },
});
```

Then add it to `ALL_RULES` in [`src/rules/index.ts`](src/rules/index.ts). That is the only
place rules are registered; the engine and reporters never change for a new rule.

Rules of thumb:

- **A false positive is a bug.** When the rule cannot decide, report with `confidence:
'low'` and say why in the message. Do not hide the finding, and do not report it as
  certain.
- **Rules are read-only.** Use only `RuleContext`. Never import or execute project files,
  spawn processes or touch the network.
- **Never let a raw secret reach a finding.** `evidence` is the branded `Redacted` type; use
  `redactSecret` for secrets. Params are scrubbed again by the engine, but do not rely on it.
- **Never crash on hostile input.** Parsers can fail; huge or minified files exist. A
  thrown error becomes a `rule-crashed` diagnostic and exit code 3.
- **Messages are complete sentences in both languages**, with `{param}` placeholders, no HTML,
  and inline code in backticks only.

### 3. Tests and docs

- Unit tests in `test/unit/rules/<family>/`: a positive and a negative case for every
  pattern, including realistic look-alikes.
- `npm run accuracy` must show the new expectation as a true positive and no false
  positives. Commit the regenerated `docs/accuracy.md`.
- `npm run docs:rules` creates `docs/rules/<rule-id>.md`. Write its two hand sections
  (what it detects; false positives and limitations); the test suite fails until you do.
- Update [docs/threat-model.md](docs/threat-model.md) with what the rule cannot see.
- Run `npm run arabic-review` and say in the PR whether the Arabic needs a native review.

## Reporting security issues

Do not open a public issue for a vulnerability in VibeGuard itself. See
[SECURITY.md](SECURITY.md).
