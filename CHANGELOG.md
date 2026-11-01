# Changelog

## [3.0.0](https://github.com/fawwazid/go-aes/compare/v2.0.0...v3.0.0) (2026-11-01)


### ⚠ BREAKING CHANGES

* prepare v2 security refactor ([#16](https://github.com/fawwazid/go-aes/issues/16))

### Features

* **aes:** initial implementation of AES modes and tests ([1d9e59a](https://github.com/fawwazid/go-aes/commit/1d9e59a648d1340041579603de53ee37ededacf4))
* prepare v2 security refactor ([#16](https://github.com/fawwazid/go-aes/issues/16)) ([402c459](https://github.com/fawwazid/go-aes/commit/402c4592ec1257fa030dd92a55c56a0032abbaaf))


### Bug Fixes

* ensure release-type is set to simple in release-please configuration ([8283c45](https://github.com/fawwazid/go-aes/commit/8283c4563ab8347246d7b1fed3cb656745de7e0e))
* **release:** configure semantic versioning ([#19](https://github.com/fawwazid/go-aes/issues/19)) ([7103e54](https://github.com/fawwazid/go-aes/commit/7103e54010b6d3ad4533b0940d4b22357aa0782e))


### Refactors

* centralize AES block creation, update GoDoc, and enhance unit tests ([df30e02](https://github.com/fawwazid/go-aes/commit/df30e028dc2a8b97f90637a7c001ff06cfb7f7e1))
* centralize AES block creation, update GoDoc, and enhance unit tests ([#6](https://github.com/fawwazid/go-aes/issues/6)) ([39c5196](https://github.com/fawwazid/go-aes/commit/39c51969f59fc84d3452b790feaf6588aaf2879b))
* centralized padding, moved tests, and updated docs to NIST … ([#2](https://github.com/fawwazid/go-aes/issues/2)) ([5834c54](https://github.com/fawwazid/go-aes/commit/5834c54c29ebe731c42a596996fa4b49d4a044e7))


### Documentation

* remove Go Report Card badge from README ([e8ddac5](https://github.com/fawwazid/go-aes/commit/e8ddac58531debb4ea1e272a4ae9693fa768bd9b))
* standardize README filename capitalization ([7ebb28d](https://github.com/fawwazid/go-aes/commit/7ebb28df9d5a6c77a6c87b14626a363a63ef1184))
* update README for clarity and structure improvements ([93d6050](https://github.com/fawwazid/go-aes/commit/93d60506abe196536755b848e5b97bc81975781b))


### Chores

* add release-please configuration for versioning ([308d3c3](https://github.com/fawwazid/go-aes/commit/308d3c339d787f033ea01dbbe362fb6e7fa87c90))
* configure Dependabot dependency updates ([d964c85](https://github.com/fawwazid/go-aes/commit/d964c85f43f983854432cf6b6ac2ba6cc9cba862))
* configure Google Release Please ([6e3d692](https://github.com/fawwazid/go-aes/commit/6e3d692aa021b002c84b800c2d50ca0239cfbeab))
* **deps:** bump golang.org/x/crypto ([98f57da](https://github.com/fawwazid/go-aes/commit/98f57da81740ccf6458c314e2502654f07d2b28a))
* **deps:** bump golang.org/x/crypto from 0.45.0 to 0.46.0 ([#5](https://github.com/fawwazid/go-aes/issues/5)) ([41a7c42](https://github.com/fawwazid/go-aes/commit/41a7c42d61abe46f740a7db2e51c3ec7600c8623))
* **deps:** bump golang.org/x/crypto from 0.46.0 to 0.49.0 ([#12](https://github.com/fawwazid/go-aes/issues/12)) ([2824f2e](https://github.com/fawwazid/go-aes/commit/2824f2e5eddeb414736762acfda6225da8041653))
* **deps:** bump golang.org/x/crypto from 0.49.0 to 0.52.0 in the go_modules group across 1 directory ([#13](https://github.com/fawwazid/go-aes/issues/13)) ([98f57da](https://github.com/fawwazid/go-aes/commit/98f57da81740ccf6458c314e2502654f07d2b28a))
* **main:** release 1.0.0 ([a6b5bf6](https://github.com/fawwazid/go-aes/commit/a6b5bf6130be258ea3ea3314c3984501294d9b32))
* **main:** release 1.0.0 ([d0492ec](https://github.com/fawwazid/go-aes/commit/d0492ece6c5dfdc876697645b9972cf4e637c0c7))
* **main:** release 1.0.1 ([#4](https://github.com/fawwazid/go-aes/issues/4)) ([c19b135](https://github.com/fawwazid/go-aes/commit/c19b13586f8f59f0fc88dd6cce89c853554a0f11))
* remove release-please workflow and changelog files ([8819e0a](https://github.com/fawwazid/go-aes/commit/8819e0aea6bc73c202396ecb67689f070e72ffe4))
* remove release-please workflow and changelog files ([#9](https://github.com/fawwazid/go-aes/issues/9)) ([b0bdaab](https://github.com/fawwazid/go-aes/commit/b0bdaab7184aedae06764314dd2304f83d5fd25b))
* reset Release Please baseline ([db4a934](https://github.com/fawwazid/go-aes/commit/db4a934e836ad8abe4588bbb88c12ad0d114ef76))
* update release type to 'go' and remove legacy config ([#8](https://github.com/fawwazid/go-aes/issues/8)) ([8232dda](https://github.com/fawwazid/go-aes/commit/8232ddadf1dac6f4e24a7f0dc02ea20f683ab667))


### Security

* harden AES modes and NIST constraints ([#14](https://github.com/fawwazid/go-aes/issues/14)) ([dc702f5](https://github.com/fawwazid/go-aes/commit/dc702f5b1ff4ef56715826db005cb1b9c59c9a3e))

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
