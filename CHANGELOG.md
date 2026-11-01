# Changelog

## [3.0.0](https://github.com/fawwazid/go-aes/compare/v2.0.0...v3.0.0) (2026-11-01)


### ⚠ BREAKING CHANGES

* prepare v2 security refactor ([#16](https://github.com/fawwazid/go-aes/issues/16))

### Features

* **aes:** initial implementation of AES modes and tests ([1d9e59a](https://github.com/fawwazid/go-aes/commit/1d9e59a648d1340041579603de53ee37ededacf4))
* prepare v2 security refactor ([#16](https://github.com/fawwazid/go-aes/issues/16)) ([402c459](https://github.com/fawwazid/go-aes/commit/402c4592ec1257fa030dd92a55c56a0032abbaaf))


### Bug Fixes

* ensure release-type is set to simple in release-please configuration ([8283c45](https://github.com/fawwazid/go-aes/commit/8283c4563ab8347246d7b1fed3cb656745de7e0e))

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
