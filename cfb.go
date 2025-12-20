package goaes

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// EncryptCFB encrypts plaintext using AES in CFB mode.
//
// NIST SP 800-38A Warning: This mode provides Confidentiality ONLY.
// It is malleable: bit-flipping attacks on ciphertext will change plaintext predictably.
//
// Recommendation: Use EncryptGCM (AEAD) instead.
//
// Parameters:
//   - key: 16, 24, or 32 bytes (AES-128, 192, or 256).
//   - plaintext: Data to be encrypted.
//
// Returns: IV prepended to ciphertext (iv||ciphertext).
func EncryptCFB(key, plaintext []byte) ([]byte, error) {
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
	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ct, plaintext)

	out := make([]byte, 0, len(iv)+len(ct))
	out = append(out, iv...)
	out = append(out, ct...)
	return out, nil
}

// DecryptCFB decrypts data produced by EncryptCFB.
// It expects the IV to be prepended to the ciphertext.
//
// Parameters:
//   - key: same key used for encryption.
//   - ciphertext: iv||ciphertext.
//
// Returns: decrypted plaintext.
func DecryptCFB(key, ciphertext []byte) ([]byte, error) {
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
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(pt, ct)

	return pt, nil
}
