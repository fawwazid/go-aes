
# go-aes

A small Go library providing AES utilities across several modes (AEAD, block, and stream modes).

Features
- AES-GCM (authenticated): `EncryptGCM` / `DecryptGCM`
- AES-CBC (block, PKCS#7 padding): `EncryptCBC` / `DecryptCBC`
- AES-ECB (block, PKCS#7 padding): `EncryptECB` / `DecryptECB` (not recommended for repeating data)
- AES-CFB (stream): `EncryptCFB` / `DecryptCFB`
- AES-OFB (stream): `EncryptOFB` / `DecryptOFB` (stdlib marks OFB deprecated; consider CTR)
- AES-CTR (stream): `EncryptCTR` / `DecryptCTR`
- AES-XTS (disk/sector mode): `EncryptXTS` / `DecryptXTS` (uses `golang.org/x/crypto/xts`)

Utilities
- `GenerateAESKey(bits)` — generate an AES key (128/192/256 bits)
- `GenerateXTSKeyForAES(bits)` — generate a combined XTS key (two AES keys concatenated)
- `GenerateNonce(size)` — generate a nonce (defaults to 12 bytes for GCM)
- Base64/Hex helpers: `EncodeBase64`, `DecodeBase64`, `HexEncode`, `HexDecode`

Installation

This project uses Go modules. The XTS implementation depends on `golang.org/x/crypto/xts`. It will be fetched automatically when running `go test`, or you can add it manually:

```bash
go get golang.org/x/crypto/xts
```

Quick example (Go)

```go
package main

import (
    "fmt"
    "log"

    goaes "github.com/fawwazid/go-aes"
)

func main() {
    key, _ := goaes.GenerateAESKey(256)
    plaintext := []byte("hello AES-GCM world")

    // AES-GCM (authenticated)
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

Running tests

```bash
go test ./...
```

Security notes
- Prefer AEAD modes (like AES-GCM) when you need both confidentiality and integrity.
- XTS is designed for disk/sector encryption and does not provide authentication — add an integrity layer if required.
- Avoid ECB for data with repeating patterns.

Contributing

Issues and pull requests are welcome.

License

Add a license of your choice to this repository if you plan to redistribute.
