package goaes

import (
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

const (
	// MaxGCMRandomNonceInvocations is the SP 800-38D per-key limit when
	// 96-bit nonces are generated randomly. Callers must rotate the key before
	// reaching this limit; this stateless package cannot count invocations.
	MaxGCMRandomNonceInvocations uint64 = 1 << 32
	maxGCMPlaintextSize          uint64 = (1 << 36) - 32
)

// EncryptGCM encrypts plaintext using AES-GCM (Galois/Counter Mode).
//
// NIST SP 800-38D Recommendation: Authenticated Encryption (AEAD).
// This mode provides both confidentiality and authenticity (AEAD).
// EncryptGCM uses a random 96-bit nonce and a 128-bit tag. SP 800-38D limits
// this construction to MaxGCMRandomNonceInvocations encryptions per key.
//
// Parameters:
//   - key: 16/24/32 bytes (AES-128/192/256). Use 32 bytes for top security.
//   - plaintext: Data to be encrypted.
//   - aad: Additional Authenticated Data (optional, can be nil). PROOF of integrity, not encrypted.
//
// Returns: nonce||ciphertext
func EncryptGCM(key, plaintext, aad []byte) ([]byte, error) {
	if uint64(len(plaintext)) > maxGCMPlaintextSize {
		return nil, errors.New("plaintext exceeds the AES-GCM size limit")
	}
	block, err := newCipherBlock(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ct := gcm.Seal(nil, nonce, plaintext, aad)

	out := make([]byte, 0, len(nonce)+len(ct))
	out = append(out, nonce...)
	out = append(out, ct...)
	return out, nil
}

// DecryptGCM decrypts data produced by EncryptGCM.
// It expects the nonce to be prepended to the ciphertext.
//
// Parameters:
//   - key: same key used for encryption.
//   - ciphertext: nonce||ciphertext.
//   - aad: same additional data used for encryption.
//
// Returns: decrypted plaintext.
func DecryptGCM(key, ciphertext, aad []byte) ([]byte, error) {
	block, err := newCipherBlock(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce := ciphertext[:nonceSize]
	ct := ciphertext[nonceSize:]
	if len(ct) < gcm.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	if uint64(len(ct)-gcm.Overhead()) > maxGCMPlaintextSize {
		return nil, errors.New("ciphertext exceeds the AES-GCM size limit")
	}

	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, err
	}
	return pt, nil
}
