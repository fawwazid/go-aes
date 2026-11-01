# Changelog

## [2.0.1](https://github.com/fawwazid/go-aes/compare/v2.0.0...v2.0.1) (2026-11-01)


### Bug Fixes

* **release:** anchor v2 patch releases to current history ([#21](https://github.com/fawwazid/go-aes/issues/21)) ([a8764b7](https://github.com/fawwazid/go-aes/commit/a8764b7b8ed7a994f45e63fe737e7e00a03e6b92))
* **release:** configure semantic versioning ([#19](https://github.com/fawwazid/go-aes/issues/19)) ([7103e54](https://github.com/fawwazid/go-aes/commit/7103e54010b6d3ad4533b0940d4b22357aa0782e))


### Chores

* configure Google Release Please ([6e3d692](https://github.com/fawwazid/go-aes/commit/6e3d692aa021b002c84b800c2d50ca0239cfbeab))
* reset Release Please baseline ([db4a934](https://github.com/fawwazid/go-aes/commit/db4a934e836ad8abe4588bbb88c12ad0d114ef76))

## v2.0.0 — 2026-10-24

Keep authenticated GCM and storage-specific XTS; remove obsolete AES modes.

### Breaking changes

- Module path is now `github.com/fawwazid/go-aes/v2`. Update imports and use Go 1.27.3 or later.
- Remove CBC, CFB, CTR, OFB, ECB, PKCS#7 helpers, and ErrInvalidCiphertext.
- XTS cryptographic operations reject FIPS mode; use GCM for application data.

### Security and maintenance

- Use Go's internal random-nonce GCM construction with a 96-bit nonce and 128-bit tag.
- Retain per-key GCM invocation limits, XTS key separation, and data-unit bounds.
- Remove redundant code, obsolete comments, and compatibility paths.
- Add regression tests, current README examples, security guidance, and CI for Linux and Windows.
- FIPS policy tests use the frozen Go module v1.0.0 in both approved and strict assessment modes. This library is not independently FIPS certified; consult SECURITY.md for deployment requirements.

### Install

```sh
go get github.com/fawwazid/go-aes/v2@v2.0.0
```

## v1.1.1 — 2026-10-14

- Harden AES mode constraints and NIST guidance; update `golang.org/x/crypto`.

## v1.1.0 — 2025-12-29

- Improve ciphertext comparison coverage and use idiomatic byte-slice comparison.

## v1.0.1 — 2025-12-08

- Correct the release type in the original Release Please configuration.

## v1.0.0 — 2025-11-26

- Initial release with AES modes and tests.
