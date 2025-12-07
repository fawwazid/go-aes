package goaes

import (
	"crypto/aes"
	"errors"

	"golang.org/x/crypto/xts"
)

// EncryptXTS encrypts plaintext using AES-XTS.
//
// NIST 2025 Status: Approved for Storage Devices (Data-at-Rest) ONLY (SP 800-38E).
// NOT intended for General Purpose encryption or Data-in-Transit.
//
// The `key` must be twice the length of the underlying AES key (i.e. 32, 48 or 64 bytes).
// `sectorNum` is the tweak (typically the sector or block number).
func EncryptXTS(key, plaintext []byte, sectorNum uint64) ([]byte, error) {
	if len(key) != 32 && len(key) != 48 && len(key) != 64 {
		return nil, errors.New("invalid XTS key size: must be 32, 48, or 64 bytes")
	}

	c, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		return nil, err
	}

	if len(plaintext)%16 != 0 {
		return nil, errors.New("plaintext length must be a multiple of 16 bytes for XTS")
	}

	out := make([]byte, len(plaintext))
	c.Encrypt(out, plaintext, sectorNum)
	return out, nil
}

// DecryptXTS decrypts ciphertext produced by EncryptXTS.
func DecryptXTS(key, ciphertext []byte, sectorNum uint64) ([]byte, error) {
	if len(key) != 32 && len(key) != 48 && len(key) != 64 {
		return nil, errors.New("invalid XTS key size: must be 32, 48, or 64 bytes")
	}

	c, err := xts.NewCipher(aes.NewCipher, key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext)%16 != 0 {
		return nil, errors.New("ciphertext length must be a multiple of 16 bytes for XTS")
	}

	out := make([]byte, len(ciphertext))
	c.Decrypt(out, ciphertext, sectorNum)
	return out, nil
}
