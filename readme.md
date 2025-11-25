# Go - Advanced Encryption Standard (AES)

A small, minimal Go library that provides AES helpers across common modes:

- AES-GCM (AEAD)
- AES-CBC (block mode with PKCS#7 padding)
- AES-ECB (block mode with PKCS#7 padding) — use only when you understand its limitations
- AES-CFB, AES-OFB, AES-CTR (stream modes)
- AES-XTS (disk/sector mode, via `golang.org/x/crypto/xts`)

The repository exposes convenient functions for encryption/decryption, key and nonce generation, and small helpers for base64/hex encoding.

**Installation**

This project uses Go modules. Add it to your project with:

```bash
go get github.com/fawwazid/go-aes@latest
```

The XTS implementation depends on `golang.org/x/crypto`; it will be fetched automatically.

**Quick Example (AES-GCM)**

```go
package main

import (
    "fmt"
    "log"

    goaes "github.com/fawwazid/go-aes"
)

func main() {
    key, err := goaes.GenerateAESKey(256)
    if err != nil {
        log.Fatal(err)
    }

    plaintext := []byte("hello AES-GCM world")

    ct, err := goaes.EncryptGCM(key, plaintext, nil)
    if err != nil {
        log.Fatal(err)
    }

    pt, err := goaes.DecryptGCM(key, ct, nil)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(string(pt))
}
```

**API / Common Functions**

- `EncryptGCM(key, plaintext, aad) ([]byte, error)` — AES-GCM encrypt
- `DecryptGCM(key, ciphertext, aad) ([]byte, error)` — AES-GCM decrypt
- `EncryptCBC` / `DecryptCBC` — CBC with PKCS#7 padding
- `EncryptECB` / `DecryptECB` — ECB with PKCS#7 padding (not recommended for variable-length, repeating data)
- `EncryptCFB` / `DecryptCFB`, `EncryptOFB` / `DecryptOFB`, `EncryptCTR` / `DecryptCTR` — stream modes
- `EncryptXTS` / `DecryptXTS` — XTS mode for disk/sector encryption
- `GenerateAESKey(bits)` — generate AES key (128, 192, or 256)
- `GenerateXTSKeyForAES(bits)` — generate combined key material for XTS (two AES keys)
- `GenerateNonce(size)` — generate a nonce (GCM commonly uses 12 bytes)

See the source for exact signatures and additional helpers (base64/hex encoders).

**Running Tests**

From the repository root run:

```bash
go test ./...
```

**Security Notes**

- Prefer AEAD modes (AES-GCM) when you need both confidentiality and integrity.
- XTS is intended for disk/sector encryption and does not provide authentication — add integrity separately if needed.
- Avoid ECB for data with repeating patterns; use authenticated or randomized modes instead.

**Contributing**

Pull requests and issues are welcome. If you add features, include tests and keep the API consistent.

**License**

This repository includes a `LICENSE` file. Choose a license before redistributing the code.
