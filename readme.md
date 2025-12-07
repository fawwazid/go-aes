# Go - Advanced Encryption Standard (AES)

[![Go Report Card](https://goreportcard.com/badge/github.com/fawwazid/go-aes)](https://goreportcard.com/report/github.com/fawwazid/go-aes)
[![Go Reference](https://pkg.go.dev/badge/github.com/fawwazid/go-aes.svg)](https://pkg.go.dev/github.com/fawwazid/go-aes)

A small, minimal Go library that provides AES helpers.

**NIST Recommendations (SP 800-38 Series)**:

- **RECOMMENDED**: AES-GCM (Authenticated Encryption).
- **Insecure**: AES-ECB (Use only for legacy compatibility).
- **Confidentiality Only**: AES-CBC, AES-CFB, AES-CTR, AES-OFB (Must use separate MAC for integrity).

Supported modes:

- **AES-GCM** (AEAD) - **Recommended**
- AES-CBC, AES-CFB, AES-OFB, AES-CTR
- AES-ECB (Insecure)
- AES-XTS (Disk/Storage only)

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

**NIST Recommendations (SP 800-38 Series)**

1.  **Authenticated Encryption (SP 800-38D)**: Prefer **AES-GCM** for all general-purpose encryption. It provides both confidentiality and data integrity (AEAD).
2.  **Key Size**: Use **32-byte (256-bit)** keys for long-term security and post-quantum resistance compatibility.
3.  **Confidentiality Modes (SP 800-38A)**: CBC, CFB, CTR, OFB. These modes provide **confidentiality only**. They are malleable and do not detect tampering. If you must use them, you **MUST** implement a separate Message Authentication Code (HMAC).
4.  **Insecure Mode (SP 800-38A)**: ECB. **Data larger than one block is insecure** in ECB mode as it reveals patterns. Use only for legacy data recovery or strictly single-block operations.
5.  **Storage Encryption (SP 800-38E)**: **AES-XTS** is recommended for data-at-rest (disk encryption) but not for data-in-transit.

**Contributing**

Pull requests and issues are welcome. If you add features, include tests and keep the API consistent.

**License**

This repository includes a `LICENSE` file. Choose a license before redistributing the code.
