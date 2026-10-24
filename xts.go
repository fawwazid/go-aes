package goaes

import (
	"crypto/aes"

	"golang.org/x/crypto/xts"
)

// MaxXTSDataUnitSize is the SP 800-38E limit of 2^20 AES blocks.
const MaxXTSDataUnitSize = (1 << 20) * aes.BlockSize

// EncryptXTS encrypts a storage data unit with a 32- or 64-byte combined key.
// Plaintext must contain complete AES blocks; sectorNum identifies the data unit.
// XTS provides no authentication and is unavailable in FIPS mode.
func EncryptXTS(key, plaintext []byte, sectorNum uint64) ([]byte, error) {
	if err := checkNonFIPSOperation(); err != nil {
		return nil, err
	}
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

// DecryptXTS decrypts EncryptXTS output using the same key and sector number.
func DecryptXTS(key, ciphertext []byte, sectorNum uint64) ([]byte, error) {
	if err := checkNonFIPSOperation(); err != nil {
		return nil, err
	}
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
