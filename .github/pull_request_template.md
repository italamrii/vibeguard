## What and why

<!-- What does this change, and why? Link the issue if there is one. -->

## Checklist

- [ ] No secret-shaped strings committed, not even fake ones (fixtures use `{{FAKE:…}}` templates)
- [ ] For rule changes: fixtures and `vg-expect` annotations were committed **before** the detector
- [ ] Positive and negative tests, including realistic look-alikes
- [ ] Clean fixture apps still have zero findings (`npm run accuracy -- --check`)
- [ ] `npm run lint`, `npm run typecheck` and `npm test` pass
- [ ] Docs updated: `npm run docs:rules`, threat model, CHANGELOG
- [ ] Arabic text added or changed? Say whether it needs a native-speaker review: <!-- yes/no -->
