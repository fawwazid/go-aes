package goaes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
)

// ErrInvalidCiphertext is returned when unauthenticated legacy ciphertext is
// malformed. A single error prevents callers from exposing padding validity.
var ErrInvalidCiphertext = errors.New("invalid ciphertext")

// GenerateKey returns a random key of the specified byte length.
// Allowed AES key lengths are 16 (AES-128), 24 (AES-192), or 32 (AES-256) bytes.
//
// NIST SP 800-57 Recommendation: Use 32 bytes (AES-256) for long-term security
// and post-quantum resistance.
func GenerateKey(size int) ([]byte, error) {
	if err := validateKeySizeLength(size); err != nil {
		return nil, err
	}
	return GenerateRandomBytes(size)
}

// GenerateAESKey creates an AES key of the specified bit length (128, 192, 256).
//
// NIST SP 800-57 Recommendation: Use bits=256 for top-secret data or long-term protection.
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
// bits is the per-key AES size. NIST SP 800-38E approves XTS-AES-128
// and XTS-AES-256, producing combined keys of 32 and 64 bytes.
func GenerateXTSKeyForAES(bits int) ([]byte, error) {
	var combinedKeyBytes int
	switch bits {
	case 128:
		combinedKeyBytes = 32
	case 256:
		combinedKeyBytes = 64
	default:
		return nil, errors.New("invalid XTS-AES bits: must be 128 or 256")
	}
	for {
		key, err := GenerateRandomBytes(combinedKeyBytes)
		if err != nil {
			return nil, err
		}
		if subtle.ConstantTimeCompare(key[:len(key)/2], key[len(key)/2:]) != 1 {
			return key, nil
		}
	}
}

// newCipherBlock creates a new AES cipher block and validates the key size.
func newCipherBlock(key []byte) (cipher.Block, error) {
	if err := validateKeySize(key); err != nil {
		return nil, err
	}
	return aes.NewCipher(key)
}

// validateKeySize checks if the key size is valid for AES (16, 24, or 32 bytes).
func validateKeySize(key []byte) error {
	return validateKeySizeLength(len(key))
}

// validateKeySizeLength checks if the given length is valid for an AES key.
func validateKeySizeLength(length int) error {
	if length != 16 && length != 24 && length != 32 {
		return errors.New("invalid key size: must be 16, 24, or 32 bytes")
	}
	return nil
}

// validateXTSKeySize checks NIST-approved XTS-AES key sizes.
func validateXTSKeySize(key []byte) error {
	if len(key) != 32 && len(key) != 64 {
		return errors.New("invalid XTS key size: must be 32 or 64 bytes")
	}
	if subtle.ConstantTimeCompare(key[:len(key)/2], key[len(key)/2:]) == 1 {
		return errors.New("invalid XTS key: the two component keys must be distinct")
	}
	return nil
}

// validateXTSDataUnit enforces the SP 800-38E data-unit limit. This package's
// XTS backend does not implement ciphertext stealing, so only complete blocks
// are supported.
func validateXTSDataUnit(length int) error {
	if length < aes.BlockSize {
		return errors.New("XTS data unit must contain at least one AES block")
	}
	if length%aes.BlockSize != 0 {
		return errors.New("XTS data unit length must be a multiple of 16 bytes")
	}
	if length > MaxXTSDataUnitSize {
		return errors.New("XTS data unit exceeds the NIST limit of 2^20 AES blocks")
	}
	return nil
}

// HexEncode returns the hex encoding of b.
func HexEncode(b []byte) string { return hex.EncodeToString(b) }

// HexDecode decodes a hex string into bytes.
func HexDecode(s string) ([]byte, error) { return hex.DecodeString(s) }

// pkcs7Pad appends PKCS#7 padding to the data.
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

// pkcs7Unpad removes PKCS#7 padding from the data and validates it.
func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, errors.New("invalid padded data length")
	}
	pad := int(data[len(data)-1])
	valid := subtle.ConstantTimeLessOrEq(1, pad) & subtle.ConstantTimeLessOrEq(pad, blockSize)
	for i := 0; i < blockSize; i++ {
		inPadding := subtle.ConstantTimeLessOrEq(i+1, pad)
		equal := subtle.ConstantTimeByteEq(data[len(data)-1-i], byte(pad))
		valid &= subtle.ConstantTimeSelect(inPadding, equal, 1)
	}
	if valid != 1 {
		return nil, errors.New("invalid PKCS#7 padding")
	}
	return data[:len(data)-pad], nil
}
