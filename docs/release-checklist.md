# Release checklist

Everything that must be true before `v0.1.0` is tagged. Automated gates run in CI on every
push. The manual tasks below cannot run in ordinary CI; record each result (who, when,
which commit) in the release PR.

Publishing to npm and the repository's visibility are maintainer decisions. Nothing in
this repository publishes automatically: the [release workflow](../.github/workflows/release.yml)
runs only on a pushed version tag and then waits for approval.

Status as of 2026-11-03.

## Manual tasks

| #   | Task                                         | Status                         |
| --- | -------------------------------------------- | ------------------------------ |
| 1   | Real SARIF upload on a throwaway public repo | **Open**                       |
| 2   | Re-check GitHub's SARIF limits               | **Open**                       |
| 3   | Visual Arabic render check                   | **Open**                       |
| 4   | Arabic proofreading sign-off                 | **Open**                       |
| 5   | Real-world validation on 3+ projects         | **1 of 3 done**                |
| 6   | Enable private vulnerability reporting       | **Open**                       |
| 7   | Release environment and npm publishing setup | **Open**                       |
| 8   | Full git history secret scan                 | **Done** (0 found, 2026-11-03) |
| 9   | Version, changelog date, merge to main       | **Open** (at release time)     |

### 1. Real SARIF upload on a throwaway public repository

Never in `italamrii/vibeguard` itself: the alerts come from the intentionally vulnerable
fixtures and would show up as public, synthetic alerts. The upload workflow refuses to run
in this repository.

- [ ] Create a throwaway **public** repository (code scanning is free for public repos).
- [ ] Push a copy of this repository (or just the workflow plus `npm ci`-able sources) and
      run _Code scanning upload (manual)_
      ([`.github/workflows/code-scanning-upload.yml`](../.github/workflows/code-scanning-upload.yml)).
- [ ] The upload is accepted with no processing errors.
- [ ] Alerts show the expected severities (critical / high / medium / low, from
      `security-severity`); `secrets/provider-key-test` shows as low.
- [ ] Rule help renders, and every "Learn more" link (`helpUri`) opens the rule page on
      `main` of `italamrii/vibeguard` (requires `feat/v1` to be merged).
- [ ] Check how the inline-suppressed result is shown (expected: not an open alert), and
      record what GitHub actually does.
- [ ] Re-running the workflow does **not** create duplicate alerts (stable
      `partialFingerprints`).
- [ ] Delete the throwaway repository.

### 2. GitHub SARIF limits

- [ ] Compare `src/reporters/sarif-github.ts` with GitHub's current "SARIF support for code
      scanning" page and update it if limits changed.

### 3. Visual Arabic render check

Automated tests check bidi isolation, and rendered pages were measured in Chromium during
development. A human check on the real renderers is still required.

- [ ] Open an Arabic Markdown report (`--format markdown --lang ar`) on GitHub (commit it
      to the throwaway repository, or paste it into an issue there) and in one other
      renderer (VS Code preview).
- [ ] Paths, rule ids, `.env`, numbers in parentheses and code blocks stay in place and in
      order; prose reads right-to-left.
- [ ] The Arabic SARIF rule help renders in the code scanning alert view (task 1).

### 4. Arabic proofreading sign-off

- [ ] A native Arabic speaker reviews [`arabic-review.md`](arabic-review.md) (every Arabic
      string in one table; regenerate with `npm run arabic-review`).
- [ ] Record the reviewer, the date and the commit reviewed. Fix and regenerate anything
      they flag.

### 5. Real-world validation on 3+ projects

Counts only, recorded in [`real-world-validation.json`](real-world-validation.json) and
rendered into [`accuracy.md`](accuracy.md). Never record names, paths or code.

- [x] Project P1 (Next.js App Router): scanned; 16 false positives and 20 false negatives
      found and fixed generically; 1 open finding.
- [ ] P1's open finding (`endpoints/unauthenticated-data-access`, medium/low) reviewed by
      the owner and recorded as true or false positive.
- [ ] Project P2.
- [ ] Project P3.

### 6. Private vulnerability reporting

- [ ] Enable it (Settings → Code security → Private vulnerability reporting), so the
      link in [`SECURITY.md`](../SECURITY.md) works.

### 7. Release environment and npm publishing

- [ ] The npm account that will publish owns the `@italamrii` scope.
- [ ] Create the `npm-release` environment (Settings → Environments) with required
      reviewers, restricted to `v*` tags.
- [ ] Either add an npm automation token as the environment secret `NPM_TOKEN`, or
      configure npm trusted publishing for `release.yml`.

### 8. Full git history secret scan (done)

- [x] `npm run scan:history` over all branches after the `feat/v1` merge: 70 commits, 24,919
      added lines, **0** secret-shaped strings (provider signatures and PEM keys).
- [x] Every distinct historical tree (69) scanned with VibeGuard's full secrets family at
      `--min-confidence low`: **0** findings.
- [x] Positive control: a planted fake key in a throwaway repository is detected.
- No history rewrite was needed. Re-run `npm run scan:history` right before tagging.

### 9. At release time

- [ ] `feat/v1` merged into `main` (keeps history; docs links in reports point at `main`).
- [ ] Version in `package.json` matches the tag; release date set in `CHANGELOG.md`.
- [ ] Accuracy (`npm run accuracy`) and benchmark (`npm run bench`) results copied into the
      release notes.
- [ ] Maintainer decision to publish; push the tag; approve the `npm-release` deployment.
- [ ] Definition of done, after publishing: `npx @italamrii/vibeguard scan ./path` works from
      the npm registry in an empty directory on Node 20 and 22 (the command it installs is
      `vibeguard`).

## Automated gates (CI on every push)

| Gate                                                                                                   | Where                    |
| ------------------------------------------------------------------------------------------------------ | ------------------------ |
| Lint, typecheck, tests, build (Node 20 and 22)                                                         | `ci.yml` → check         |
| Fixture accuracy: no false positive, no unexpected miss                                                | `ci.yml` → check         |
| SARIF validates against the OASIS 2.1.0 schema and GitHub's constraints                                | `ci.yml` → check         |
| Self-scan of this repository at `--fail-on low`                                                        | `ci.yml` → check         |
| Rule docs current; every docs URL in reports resolves; no broken Markdown links                        | `ci.yml` → check         |
| SQL parser installs and runs on Linux, macOS, Windows (Node 20 and 22)                                 | `ci.yml` → portability   |
| Dependency license policy; `npm audit` with zero runtime advisories                                    | `ci.yml` → supply-chain  |
| Tarball allowlist (no fixtures, tests, scripts, sources, maps, env files) and no secret-shaped content | `ci.yml` → package       |
| Packed tarball installs in a clean directory; `--version`, `rules`, `scan` work (Node 20 and 22)       | `ci.yml` → install-smoke |
