package goaes

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// EncryptCTR encrypts plaintext using AES in CTR mode (Counter Mode).
//
// NIST SP 800-38A Warning: This mode provides Confidentiality ONLY.
// It is malleable: bit-flipping attacks on ciphertext will directly flip bits in plaintext.
// NEVER reuse a (Key, IV) pair.
//
// Recommendation: Use EncryptGCM (AEAD) instead.
//
// Parameters:
//   - key: 16, 24, or 32 bytes (AES-128, 192, or 256).
//   - plaintext: Data to be encrypted.
//
// Returns: IV prepended to ciphertext (iv||ciphertext).
func EncryptCTR(key, plaintext []byte) ([]byte, error) {
	block, err := newCipherBlock(key)
	if err != nil {
		return nil, err
	}

	bs := block.BlockSize()
	iv := make([]byte, bs)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	ct := make([]byte, len(plaintext))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(ct, plaintext)

	out := make([]byte, 0, len(iv)+len(ct))
	out = append(out, iv...)
	out = append(out, ct...)
	return out, nil
}

// DecryptCTR decrypts data produced by EncryptCTR.
// It expects the IV to be prepended to the ciphertext.
//
// Parameters:
//   - key: same key used for encryption.
//   - ciphertext: iv||ciphertext.
//
// Returns: decrypted plaintext.
func DecryptCTR(key, ciphertext []byte) ([]byte, error) {
	block, err := newCipherBlock(key)
	if err != nil {
		return nil, err
	}

	bs := block.BlockSize()
	if len(ciphertext) < bs {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:bs]
	ct := ciphertext[bs:]

	pt := make([]byte, len(ct))
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(pt, ct)

	return pt, nil
}
