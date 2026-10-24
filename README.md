# go-aes

Install: `go get github.com/fawwazid/go-aes/v2@v2.0.0`.
See [v2 release notes](CHANGELOG.md) for breaking changes.

AES-GCM authenticated encryption and AES-XTS storage helpers for Go 1.27.3.

## Usage

```go
package main

import (
 "fmt"
 "log"
 goaes "github.com/fawwazid/go-aes/v2"
)

func main() {
 key, err := goaes.GenerateAESKey(256)
 if err != nil { log.Fatal(err) }
 aad := []byte("record-type:v1")
 ciphertext, err := goaes.EncryptGCM(key, []byte("message"), aad)
 if err != nil { log.Fatal(err) }
 plaintext, err := goaes.DecryptGCM(key, ciphertext, aad)
 if err != nil { log.Fatal(err) }
 fmt.Println(string(plaintext))
}
```

## API and security

- GCM: `EncryptGCM` and `DecryptGCM`; random 96-bit nonce and 128-bit tag.
  The output is nonce || ciphertext || tag. Supply the same AAD to decrypt.
- XTS: `GenerateXTSKeyForAES`, `EncryptXTS`, and `DecryptXTS`.
  Only storage data units made of complete 16-byte blocks are supported.
  Maximum data unit: 2^20 blocks. XTS provides no authentication.
- Key/random helpers: `GenerateKey`, `GenerateAESKey`, `GenerateRandomBytes`,
  and `GenerateNonce`. GCM generates its own nonce internally.
- Encoding: `EncodeBase64`, `DecodeBase64`, `HexEncode`, `HexDecode`.

Rotate GCM keys before 2^32 encryptions, accounting for all instances sharing
the key. XTS requires distinct key halves and a data-unit-specific sector number.
The external XTS implementation returns `ErrFIPSUnsupported` in FIPS mode.

## Breaking changes

CBC, CFB, CTR, OFB, ECB, PKCS#7 padding helpers, and their error surface have
been removed. There are no deprecated wrappers or alternate-mode fallbacks.
Applications must use GCM for authenticated application data or XTS for its
documented storage use case.

See [SECURITY.md](SECURITY.md) for FIPS builds and validation scope.
Run `go test ./...` and `go vet ./...`. License: [MIT](LICENSE).
