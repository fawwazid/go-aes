package goaes

import (
	"crypto/aes"

	"golang.org/x/crypto/xts"
)

// MaxXTSDataUnitSize is the SP 800-38E limit of 2^20 AES blocks.
const MaxXTSDataUnitSize = (1 << 20) * aes.BlockSize

// EncryptXTS encrypts plaintext using AES-XTS.
//
// NIST SP 800-38E Recommendation: Approved for Storage Devices (Data-at-Rest) ONLY.
// NOT intended for General Purpose encryption or Data-in-Transit.
// This implementation handles complete AES blocks only and does not implement
// ciphertext stealing.
//
// Parameters:
//   - key: 32 bytes for XTS-AES-128 or 64 bytes for XTS-AES-256.
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

	if err := validateXTSDataUnit(len(plaintext)); err != nil {
		return nil, err
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

	if err := validateXTSDataUnit(len(ciphertext)); err != nil {
		return nil, err
	}

	out := make([]byte, len(ciphertext))
	c.Decrypt(out, ciphertext, sectorNum)
	return out, nil
}
