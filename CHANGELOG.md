# Changelog

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
