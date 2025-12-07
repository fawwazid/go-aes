package goaes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// EncryptCBC encrypts plaintext using AES-CBC with PKCS#7 padding.
//
// NIST SP 800-38A Warning: This mode provides Confidentiality ONLY.
// It DOES NOT provide integrity or authenticity.
// Vulnerable to Padding Oracle attacks if not implemented with constant-time MAC.
//
// Recommendation: Use EncryptGCM (AEAD) instead.
//
// Returns: IV prepended to ciphertext (iv||ciphertext).
func EncryptCBC(key, plaintext []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("invalid key size: must be 16, 24, or 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	bs := block.BlockSize()
	padded := pkcs7Pad(plaintext, bs)

	iv := make([]byte, bs)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return nil, err
	}

	ct := make([]byte, len(padded))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ct, padded)

	out := make([]byte, 0, len(iv)+len(ct))
	out = append(out, iv...)
	out = append(out, ct...)
	return out, nil
}

// DecryptCBC decrypts data produced by EncryptCBC (expects iv prepended).
func DecryptCBC(key, ciphertext []byte) ([]byte, error) {
	if len(key) != 16 && len(key) != 24 && len(key) != 32 {
		return nil, errors.New("invalid key size: must be 16, 24, or 32 bytes")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	bs := block.BlockSize()
	if len(ciphertext) < bs {
		return nil, errors.New("ciphertext too short")
	}

	iv := ciphertext[:bs]
	ct := ciphertext[bs:]

	if len(ct)%bs != 0 {
		return nil, errors.New("ciphertext is not a multiple of block size")
	}

	pt := make([]byte, len(ct))
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(pt, ct)

	return pkcs7Unpad(pt, bs)
}
