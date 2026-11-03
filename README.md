# VibeGuard

> **Status: under active development (v1 in progress).** Rules are not shipped yet; see the
> milestone plan in the repository's issues and `docs/adr/`.

VibeGuard is an open-source CLI that statically scans AI-generated ("vibe-coded") web
projects, such as Next.js, React and Node apps on Supabase or Firebase, for the security
and data-integrity flaws they commonly ship with.

**Scan only code you own or are authorized to assess.**

VibeGuard is strictly local and read-only. It never modifies the scanned project, never
makes network calls, and never sends code or findings anywhere. Secrets are never printed
in full: every output shows only the first 4 characters and the length.

## License

Apache-2.0. See [LICENSE](LICENSE).
