package goaes

import (
	"crypto/aes"
	"errors"

	"golang.org/x/crypto/xts"
)

// EncryptXTS encrypts plaintext using AES-XTS.
//
// NIST SP 800-38E Recommendation: Approved for Storage Devices (Data-at-Rest) ONLY.
// NOT intended for General Purpose encryption or Data-in-Transit.
//
// Parameters:
//   - key: twice the length of the underlying AES key (32, 48 or 64 bytes).
//   - plaintext: Data to be encrypted (must be multiple of 16 bytes).
//   - sectorNum: the tweak (typically the sector or block number).
//
// Returns: ciphertext.
func EncryptXTS(key, plaintext []byte, sectorNum uint64) ([]byte, error) {
	if err := validateXTSKeySize(key); err != nil {
		return nil, err
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
//
// Parameters:
//   - key: same key used for encryption.
//   - ciphertext: Data to be decrypted.
//   - sectorNum: same sector number used for encryption.
//
// Returns: decrypted plaintext.
func DecryptXTS(key, ciphertext []byte, sectorNum uint64) ([]byte, error) {
	if err := validateXTSKeySize(key); err != nil {
		return nil, err
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
