package goaes

import (
	"crypto/cipher"
	"errors"
)

const (
	// MaxGCMRandomNonceInvocations is the SP 800-38D per-key limit when
	// 96-bit nonces are generated randomly. Callers must rotate the key before
	// reaching this limit; this stateless package cannot count invocations.
	MaxGCMRandomNonceInvocations uint64 = 1 << 32
	maxGCMPlaintextSize          uint64 = (1 << 36) - 32
)

// EncryptGCM returns nonce || ciphertext || tag using AES-GCM.
// The key must contain 16, 24, or 32 bytes. Optional AAD is authenticated,
// not encrypted. A random 96-bit nonce and 128-bit tag are included.
// Rotate the key before MaxGCMRandomNonceInvocations encryptions.
func EncryptGCM(key, plaintext, aad []byte) ([]byte, error) {
	if uint64(len(plaintext)) > maxGCMPlaintextSize {
		return nil, errors.New("plaintext exceeds the AES-GCM size limit")
	}
	block, err := newCipherBlock(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}

	return gcm.Seal(nil, nil, plaintext, aad), nil
}

// DecryptGCM verifies and decrypts EncryptGCM output using the same key and AAD.
func DecryptGCM(key, ciphertext, aad []byte) ([]byte, error) {
	block, err := newCipherBlock(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < gcm.Overhead() {
		return nil, errors.New("ciphertext too short")
	}
	if uint64(len(ciphertext)-gcm.Overhead()) > maxGCMPlaintextSize {
		return nil, errors.New("ciphertext exceeds the AES-GCM size limit")
	}

	return gcm.Open(nil, nil, ciphertext, aad)
}
