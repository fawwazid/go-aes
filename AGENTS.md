# Agent instructions

This repository is the `go-aes` Go module. Keep changes within this module
unless the task explicitly spans other repositories. Preserve existing user
changes. Do not create or edit changelogs; Release Please generates them.

## Security and API

- Prefer AES-GCM for authenticated application data.
- Keep AES-XTS limited to storage data units; it does not authenticate data and
  its implementation is unavailable in FIPS mode.
- Preserve documented nonce, key-rotation, input-size, and data-unit limits.
- Do not restore removed unauthenticated modes or compatibility fallbacks.
- Describe FIPS support as conditional on the validated Go module, approved
  mode, and operating environment; this package is not independently certified.

## Development

- Workspace mail invariant: `go-mail` caps messages at 1,000 recipients, 100
  attachments, and 25 MiB; untrusted attachment bytes use its checked API.
- Workspace MFA invariant: `ConstantTimeCompare` rejects strings longer than
  4,096 UTF-8 bytes before allocating byte slices.

- Target the Go version in `go.mod`; format Go changes with `gofmt`.
- Keep `README.md` and `SECURITY.md` aligned with exported APIs and limits.
- Remove only clearly unused internal code; preserve exported APIs unless a
  breaking change is explicitly requested.
- Add or update regression tests for every code change and run the affected
  module's complete test suite before finishing. Run `go vet ./...` as well.
- Review changes against applicable NIST SP 800-38D/38E, FIPS, and OWASP
  guidance. Preserve authenticated GCM use; state that XTS is unauthenticated.
- For every workspace code, test, or security-policy change, review and update
  all eight module-level `AGENTS.md` files in the same change set so their
  constraints and test-coverage notes stay aligned. Keep updates concise; this
  is not a changelog.

## Test coverage notes

- `utils_test.go` covers invalid random-byte sizes and the valid small-size
  case, including the public allocation limit.

## Release workflow

- Use Conventional Commit pull request titles so squash merges produce the
  intended SemVer bump: `fix:` for patch, `feat:` for minor, and `!` or
  `BREAKING CHANGE:` for major. Use `fix(security):` for security fixes;
  `security:` alone does not bump a version.
- `docs:`, `test:`, `chore:`, and `ci:` do not trigger a release. Release
  Please opens or updates a release pull request; merge that generated PR to
  create the version tag and GitHub release.
- Never create or edit changelogs manually; Release Please generates them.