# Go - Advanced Encryption Standard (AES)

[![Go Reference](https://pkg.go.dev/badge/github.com/fawwazid/go-aes.svg)](https://pkg.go.dev/github.com/fawwazid/go-aes)
[![Go Report Card](https://goreportcard.com/badge/github.com/fawwazid/go-aes)](https://goreportcard.com/report/github.com/fawwazid/go-aes)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Secure and easy-to-use Go library that provides AES helpers with a focus on compliance with NIST standards (SP 800-38 series).

## Features

- **AES-GCM** (Authenticated Encryption) - **Highly Recommended**
- **AES-XTS** (XEX-based-tweaked-codebook-mode with ciphertext stealing) - **For Disk Encryption**
- **AES-CBC, AES-CFB, AES-OFB, AES-CTR** (Confidentiality modes)
- **AES-ECB** (Included for legacy compatibility, use with caution)
- Secure key and nonce generation using `crypto/rand`.
- Helpers for Base64 and Hex encoding.
- PKCS#7 padding implemented for block modes.

## NIST Compliance (SP 800-38 Series)

This library is designed following NIST recommendations:

1.  **Authenticated Encryption ([SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final))**: **AES-GCM** is the preferred choice for most applications as it provides both confidentiality and data integrity (AEAD).
2.  **Key Size**: Always prefer **256-bit (32-byte)** keys for maximum security and post-quantum resistance.
3.  **Data-at-Rest ([SP 800-38E](https://csrc.nist.gov/publications/detail/sp/800-38e/final))**: **AES-XTS** is the standard for disk and storage encryption.
4.  **Legacy Modes ([SP 800-38A](https://csrc.nist.gov/publications/detail/sp/800-38a/final))**: CBC, CFB, CTR, and OFB provide **confidentiality only**. If you use these, you should implement a separate Message Authentication Code (HMAC) to ensure integrity.
5.  **Insecure Mode**: **AES-ECB** is insecure for data larger than one block. Use it only for single-block operations or legacy system interoperability.

## Installation

```bash
go get github.com/fawwazid/go-aes@latest
```

## Quick Start

### AES-GCM (Recommended)

```go
package main

import (
    "fmt"
    "log"

    goaes "github.com/fawwazid/go-aes"
)

func main() {
    // Generate a secure 256-bit key
    key, err := goaes.GenerateAESKey(256)
    if err != nil {
        log.Fatal(err)
    }

    plaintext := []byte("secret message for AES-GCM")

    // Encrypt (nonce is automatically generated and prepended)
    ciphertext, err := goaes.EncryptGCM(key, plaintext, nil)
    if err != nil {
        log.Fatal(err)
    }

    // Decrypt
    decrypted, err := goaes.DecryptGCM(key, ciphertext, nil)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Println(string(decrypted))
}
```

## API Overview

### Encryption / Decryption

| Mode | Encryption | Decryption | Note |
|---|---|---|---|
| **GCM** | `EncryptGCM(key, pt, aad)` | `DecryptGCM(key, ct, aad)` | **Recommended (AEAD)** |
| **XTS** | `EncryptXTS(key, pt, sector)` | `DecryptXTS(key, ct, sector)` | For Disk/Storage |
| **CBC** | `EncryptCBC(key, pt)` | `DecryptCBC(key, ct)` | Confidentiality only |
| **CFB** | `EncryptCFB(key, pt)` | `DecryptCFB(key, ct)` | Confidentiality only |
| **CTR** | `EncryptCTR(key, pt)` | `DecryptCTR(key, ct)` | Confidentiality only |
| **OFB** | `EncryptOFB(key, pt)` | `DecryptOFB(key, ct)` | Confidentiality only |
| **ECB** | `EncryptECB(key, pt)` | `DecryptECB(key, ct)` | **Insecure** |

### Utilities

- `GenerateAESKey(bits)`: Generate a random key (128, 192, or 256 bits).
- `GenerateNonce(size)`: Generate a random nonce.
- `EncodeBase64(data)` / `DecodeBase64(string)`: Base64 helpers.
- `HexEncode(data)` / `HexDecode(string)`: Hex helpers.

## Running Tests

```bash
go test -v ./...
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
