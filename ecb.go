package goaes

import (
	"errors"
)

// EncryptECB encrypts plaintext using AES in ECB mode with PKCS#7 padding.
//
// NIST SP 800-38A Warning: INSECURE MODE.
// Do NOT use for data larger than one block. Patterns in plaintext remain visible in ciphertext.
// This mode is provided for legacy compatibility only.
//
// Recommendation: Use EncryptGCM (AEAD) instead.
//
// Parameters:
//   - key: 16, 24, or 32 bytes (AES-128, 192, or 256).
//   - plaintext: Data to be encrypted.
//
// Returns: ciphertext (no IV used in ECB).
func EncryptECB(key, plaintext []byte) ([]byte, error) {
	block, err := newCipherBlock(key)
	if err != nil {
		return nil, err
	}

	bs := block.BlockSize()
	padded := pkcs7Pad(plaintext, bs)

	ct := make([]byte, len(padded))
	for i := 0; i < len(padded); i += bs {
		block.Encrypt(ct[i:i+bs], padded[i:i+bs])
	}

	return ct, nil
}

// DecryptECB decrypts ciphertext produced by EncryptECB and removes PKCS#7 padding.
//
// Parameters:
//   - key: same key used for encryption.
//   - ciphertext: Data to be decrypted.
//
// Returns: decrypted plaintext (unpadded).
func DecryptECB(key, ciphertext []byte) ([]byte, error) {
	block, err := newCipherBlock(key)
	if err != nil {
		return nil, err
	}

	bs := block.BlockSize()
	if len(ciphertext) == 0 || len(ciphertext)%bs != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	pt := make([]byte, len(ciphertext))
	for i := 0; i < len(ciphertext); i += bs {
		block.Decrypt(pt[i:i+bs], ciphertext[i:i+bs])
	}

	return pkcs7Unpad(pt, bs)
}
