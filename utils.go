package goaes

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
)

// GenerateKey returns a random key of the specified byte length.
// Allowed AES key lengths are 16, 24, or 32 bytes. Returns an error otherwise.
func GenerateKey(size int) ([]byte, error) {
	if size != 16 && size != 24 && size != 32 {
		return nil, errors.New("invalid key size: must be 16, 24, or 32 bytes")
	}
	return GenerateRandomBytes(size)
}

// GenerateAESKey creates an AES key of the specified bit length (128, 192, 256).
func GenerateAESKey(bits int) ([]byte, error) {
	switch bits {
	case 128:
		return GenerateKey(16)
	case 192:
		return GenerateKey(24)
	case 256:
		return GenerateKey(32)
	default:
		return nil, errors.New("invalid AES bits: must be 128, 192, or 256")
	}
}

// GenerateNonce returns a random nonce of the given size in bytes.
// If size is 0, it returns a 12-byte nonce (recommended for GCM).
func GenerateNonce(size int) ([]byte, error) {
	if size == 0 {
		size = 12
	}
	if size <= 0 {
		return nil, errors.New("nonce size must be positive")
	}
	return GenerateRandomBytes(size)
}

// EncodeBase64 returns a Base64 encoding of the input bytes.
func EncodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

// DecodeBase64 decodes a Base64 string into bytes.
func DecodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

// GenerateRandomBytes returns securely-generated random bytes of length n.
// It is a thin wrapper over crypto/rand.
func GenerateRandomBytes(n int) ([]byte, error) {
	if n <= 0 {
		return nil, errors.New("length must be positive")
	}
	b := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return nil, err
	}
	return b, nil
}

// GenerateXTSKeyForAES generates a combined XTS key for AES-XTS.
// `bits` is the AES key size in bits (128, 192, 256). The returned key
// length will be twice the AES key length (32, 48, 64 bytes).
func GenerateXTSKeyForAES(bits int) ([]byte, error) {
	perKeyBytes, err := aesKeyBytesFromBits(bits)
	if err != nil {
		return nil, err
	}
	return GenerateRandomBytes(perKeyBytes * 2)
}

// aesKeyBytesFromBits maps AES bit sizes to key byte lengths.
func aesKeyBytesFromBits(bits int) (int, error) {
	switch bits {
	case 128:
		return 16, nil
	case 192:
		return 24, nil
	case 256:
		return 32, nil
	default:
		return 0, errors.New("invalid AES bits: must be 128, 192, or 256")
	}
}

// HexEncode returns the hex encoding of b.
func HexEncode(b []byte) string { return hex.EncodeToString(b) }

// HexDecode decodes a hex string into bytes.
func HexDecode(s string) ([]byte, error) { return hex.DecodeString(s) }
