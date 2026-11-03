# Security policy

VibeGuard is a security tool, and it runs on code that may contain real secrets. We take
vulnerabilities in VibeGuard itself seriously.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a vulnerability.**

Report it privately through GitHub's private vulnerability reporting:
**[Report a vulnerability](https://github.com/italamrii/vibeguard/security/advisories/new)**
(repository → Security → Advisories → "Report a vulnerability").

Please include:

- the VibeGuard version (`vibeguard --version`), Node.js version and operating system;
- what you did, what happened, and what you expected;
- a minimal project or file that reproduces it. **Use fake values. Never send real secrets,
  real credentials or code you are not allowed to share.**

What to expect:

- an acknowledgement within 7 days;
- an assessment, and a fix or mitigation plan, as soon as we can; we will keep you updated;
- credit in the advisory and the changelog, if you want it.

VibeGuard is maintained by volunteers, so these are goals, not contractual deadlines.

## Supported versions

Until 1.0, only the latest released version receives security fixes.

## Scope

In scope: vulnerabilities in VibeGuard's own code and its published npm package, for example:

- a secret printed in full, or a redaction bypass, in any output format or language;
- network access, or code or findings sent anywhere;
- VibeGuard writing to, modifying or deleting files in the scanned project;
- code execution from a scanned project (VibeGuard must never execute scanned code), or
  an escape outside the scan root (symlinks, path traversal);
- report injection: scanned content that manipulates the terminal (escape sequences), the
  Markdown or SARIF output, or what a reviewer sees (bidi tricks);
- a crash or resource exhaustion that makes a scan report "clean" instead of incomplete;
- problems in the release pipeline or package contents (for example a file in the tarball
  that should not be there).

Out of scope (please open a normal issue instead):

- **false negatives and false positives** of the rules: these are bugs, but not security
  vulnerabilities; the [false positive template](https://github.com/italamrii/vibeguard/issues/new/choose) helps;
- the documented limitations in [docs/threat-model.md](docs/threat-model.md);
- a project's own `.vibeguard.yml` disabling rules (documented: use `--config` from a
  trusted path in CI);
- vulnerabilities in dependencies that do not affect VibeGuard; report those upstream.

## Safe harbor

We consider security research on VibeGuard carried out in good faith and in line with this
policy to be authorized. We will not pursue or support legal action against you for it,
provided you:

- test only against VibeGuard itself, on your own machines and with code you own or are
  authorized to use;
- do not access, modify or exfiltrate data that is not yours, and do not use real third-party
  secrets in reports;
- give us reasonable time to fix the issue before disclosing it publicly, and coordinate the
  disclosure date with us.

If in doubt about whether something is in scope or allowed, ask first in a private report.
