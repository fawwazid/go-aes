package goaes

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
)

// GenerateKey returns a random key of the specified byte length.
// Allowed AES key lengths are 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes.
//
// NIST 2025 Recommendation: Use 32 bytes (AES-256) for long-term security
// and post-quantum resistance.
func GenerateKey(size int) ([]byte, error) {
	if size != 16 && size != 24 && size != 32 {
		return nil, errors.New("invalid key size: must be 16, 24, or 32 bytes")
	}
	return GenerateRandomBytes(size)
}

// GenerateAESKey creates an AES key of the specified bit length (128, 192, 256).
//
// NIST 2025 Recommendation: Use bits=256 for top-secret data or long-term protection.
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

func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - (len(data) % blockSize)
	if pad == 0 {
		pad = blockSize
	}
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid padded data length")
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize {
		return nil, errors.New("invalid padding size")
	}
	// verify padding bytes
	for i := len(data) - pad; i < len(data); i++ {
		if int(data[i]) != pad {
			return nil, errors.New("invalid padding")
		}
	}
	return data[:len(data)-pad], nil
}
