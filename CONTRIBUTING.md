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
