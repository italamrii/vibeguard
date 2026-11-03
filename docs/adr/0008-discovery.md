# ADR-0008: File discovery, .gitignore semantics and git-tracked files

- Status: Accepted
- Date: 2026-11-03

## Context

Requirements: respect `.gitignore`; skip `node_modules` and build output; handle 5k-file
repos fast; detect `.env` files that are **committed**; never follow paths out of the
project; never execute project code.

## Decision

- **Async walker** with bounded directory concurrency (32). `HARD_SKIP_DIRS` covers
  dependency, VCS and build-output directories (`node_modules`, `.git`, `.next`, `dist`,
  `build`, `out`, `coverage`, …). Lockfiles, binaries (by extension) and `*.min.js` are
  never read.
- **Gitignore semantics** come from the `ignore` package. It applies `.gitignore` files at
  every level (deeper files override shallower ones, and negations re-include), plus
  `.gitignore` files _above_ the scan root up to the git root, plus `.git/info/exclude`.
  Like git, we do not descend into ignored directories.
- **Committed is not the same as "not ignored".** When the root is inside a git work tree,
  we run `git ls-files -z --cached` once. A tracked file is in the repository even if it is
  now listed in `.gitignore`, which is the classic "added .env to .gitignore after
  committing it" mistake. We still descend into an ignored directory if it contains tracked
  files.
- **Running git safely.** The scanned repo's `.git/config` can name programs that git runs
  implicitly. We pass `-c core.fsmonitor=false -c core.hooksPath=/dev/null` and related
  overrides, disable system and global config, set `safe.directory` for this single
  invocation, and use `execFile` with no shell and a timeout. If git is missing or fails,
  we fall back to `.gitignore` rules and record an `info` diagnostic.
- **Env files are kept even when ignored** (`gitIgnored: true`). A gitignored
  `.env.local` cannot leak through git, but `NEXT_PUBLIC_*` values in it still leak
  through the client bundle. Rules decide what to report based on the flags.
- **Symlinks are never followed.** They could escape the root or create cycles. Each one
  produces an `info` diagnostic.
- **Size limits.** Files over 5 MiB are skipped with a diagnostic. Files over 1 MiB are
  streamed line by line and never held whole in memory or parsed into an AST.

## Consequences

- Behaviour matches what is in, or would be in, the repository, which is what users expect
  from "respect .gitignore".
- Files inside a symlinked directory are not scanned. A monorepo that symlinks packages
  should scan each package root directly.
