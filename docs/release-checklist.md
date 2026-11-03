# Release checklist

Tasks that cannot run in ordinary CI. Each must be done, and its result recorded in the release
PR, before tagging a release.

- [ ] **Real GitHub code scanning upload.** Run the _Code scanning upload (manual)_ workflow
      (`.github/workflows/code-scanning-upload.yml`) on a public repository or one with GitHub
      Advanced Security. Confirm in the Security tab that:
  - the upload is accepted with no processing errors;
  - alerts show the right severity (critical / high / medium / low from `security-severity`),
    the rule help renders, and the "Learn more" link (`helpUri`) works;
  - the inline-suppressed result is shown as dismissed, not as an open alert;
  - re-running the workflow does **not** create duplicate alerts (stable `partialFingerprints`).
    Then dismiss the synthetic alerts or delete the analysis.
- [ ] **Re-check GitHub's SARIF limits** against GitHub's current "SARIF support for code
      scanning" page and update `src/reporters/sarif-github.ts` if they changed.
- [ ] **Arabic proofreading.** A native speaker reviews `docs/arabic-review.md`. Record who
      reviewed and which version.
- [ ] **Arabic rendering spot check.** Open an Arabic Markdown report on GitHub and in one
      other renderer (VS Code preview) and check that paths, rule ids and `.env` stay in place.
- [ ] Accuracy (`npm run accuracy`) and the benchmark (`npm run bench`) are recorded in the
      release notes.
