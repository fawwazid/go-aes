package goaes

import (
	"bytes"
	"crypto/cipher"
	"testing"
)

// TestValidateKeySizeLength tests the validateKeySizeLength function with valid and invalid key lengths.
func TestValidateKeySizeLength(t *testing.T) {
	tests := []struct {
		name    string
		length  int
		wantErr bool
	}{
		{
			name:    "valid 16-byte key (AES-128)",
			length:  16,
			wantErr: false,
		},
		{
			name:    "valid 24-byte key (AES-192)",
			length:  24,
			wantErr: false,
		},
		{
			name:    "valid 32-byte key (AES-256)",
			length:  32,
			wantErr: false,
		},
		{
			name:    "invalid 0-byte key",
			length:  0,
			wantErr: true,
		},
		{
			name:    "invalid 15-byte key",
			length:  15,
			wantErr: true,
		},
		{
			name:    "invalid 17-byte key",
			length:  17,
			wantErr: true,
		},
		{
			name:    "invalid 23-byte key",
			length:  23,
			wantErr: true,
		},
		{
			name:    "invalid 25-byte key",
			length:  25,
			wantErr: true,
		},
		{
			name:    "invalid 31-byte key",
			length:  31,
			wantErr: true,
		},
		{
			name:    "invalid 33-byte key",
			length:  33,
			wantErr: true,
		},
		{
			name:    "invalid 64-byte key",
			length:  64,
			wantErr: true,
		},
		{
			name:    "invalid negative length",
			length:  -1,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKeySizeLength(tt.length)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateKeySizeLength(%d) error = %v, wantErr %v", tt.length, err, tt.wantErr)
			}
		})
	}
}

// TestValidateKeySize tests the validateKeySize function with valid and invalid keys.
func TestValidateKeySize(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		wantErr bool
	}{
		{
			name:    "valid 16-byte key (AES-128)",
			key:     make([]byte, 16),
			wantErr: false,
		},
		{
			name:    "valid 24-byte key (AES-192)",
			key:     make([]byte, 24),
			wantErr: false,
		},
		{
			name:    "valid 32-byte key (AES-256)",
			key:     make([]byte, 32),
			wantErr: false,
		},
		{
			name:    "invalid nil key",
			key:     nil,
			wantErr: true,
		},
		{
			name:    "invalid empty key",
			key:     []byte{},
			wantErr: true,
		},
		{
			name:    "invalid 15-byte key",
			key:     make([]byte, 15),
			wantErr: true,
		},
		{
			name:    "invalid 17-byte key",
			key:     make([]byte, 17),
			wantErr: true,
		},
		{
			name:    "invalid 23-byte key",
			key:     make([]byte, 23),
			wantErr: true,
		},
		{
			name:    "invalid 25-byte key",
			key:     make([]byte, 25),
			wantErr: true,
		},
		{
			name:    "invalid 31-byte key",
			key:     make([]byte, 31),
			wantErr: true,
		},
		{
			name:    "invalid 33-byte key",
			key:     make([]byte, 33),
			wantErr: true,
		},
		{
			name:    "invalid 1-byte key",
			key:     make([]byte, 1),
			wantErr: true,
		},
		{
			name:    "invalid 8-byte key",
			key:     make([]byte, 8),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateKeySize(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateKeySize(key of length %d) error = %v, wantErr %v", len(tt.key), err, tt.wantErr)
			}
		})
	}
}

// TestValidateXTSKeySize tests the validateXTSKeySize function with valid and invalid XTS keys.
func TestValidateXTSKeySize(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		wantErr bool
	}{
		{
			name:    "valid 32-byte XTS key (AES-128)",
			key:     make([]byte, 32),
			wantErr: false,
		},
		{
			name:    "valid 48-byte XTS key (AES-192)",
			key:     make([]byte, 48),
			wantErr: false,
		},
		{
			name:    "valid 64-byte XTS key (AES-256)",
			key:     make([]byte, 64),
			wantErr: false,
		},
		{
			name:    "invalid nil key",
			key:     nil,
			wantErr: true,
		},
		{
			name:    "invalid empty key",
			key:     []byte{},
			wantErr: true,
		},
		{
			name:    "invalid 16-byte key (regular AES key)",
			key:     make([]byte, 16),
			wantErr: true,
		},
		{
			name:    "invalid 24-byte key (regular AES key)",
			key:     make([]byte, 24),
			wantErr: true,
		},
		{
			name:    "invalid 31-byte key",
			key:     make([]byte, 31),
			wantErr: true,
		},
		{
			name:    "invalid 33-byte key",
			key:     make([]byte, 33),
			wantErr: true,
		},
		{
			name:    "invalid 47-byte key",
			key:     make([]byte, 47),
			wantErr: true,
		},
		{
			name:    "invalid 49-byte key",
			key:     make([]byte, 49),
			wantErr: true,
		},
		{
			name:    "invalid 63-byte key",
			key:     make([]byte, 63),
			wantErr: true,
		},
		{
			name:    "invalid 65-byte key",
			key:     make([]byte, 65),
			wantErr: true,
		},
		{
			name:    "invalid 128-byte key",
			key:     make([]byte, 128),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateXTSKeySize(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateXTSKeySize(key of length %d) error = %v, wantErr %v", len(tt.key), err, tt.wantErr)
			}
		})
	}
}

// TestNewCipherBlock tests the newCipherBlock function with valid and invalid keys.
func TestNewCipherBlock(t *testing.T) {
	tests := []struct {
		name    string
		key     []byte
		wantErr bool
	}{
		{
			name:    "valid 16-byte key (AES-128)",
			key:     make([]byte, 16),
			wantErr: false,
		},
		{
			name:    "valid 24-byte key (AES-192)",
			key:     make([]byte, 24),
			wantErr: false,
		},
		{
			name:    "valid 32-byte key (AES-256)",
			key:     make([]byte, 32),
			wantErr: false,
		},
		{
			name:    "invalid nil key",
			key:     nil,
			wantErr: true,
		},
		{
			name:    "invalid empty key",
			key:     []byte{},
			wantErr: true,
		},
		{
			name:    "invalid 15-byte key",
			key:     make([]byte, 15),
			wantErr: true,
		},
		{
			name:    "invalid 17-byte key",
			key:     make([]byte, 17),
			wantErr: true,
		},
		{
			name:    "invalid 8-byte key",
			key:     make([]byte, 8),
			wantErr: true,
		},
		{
			name:    "invalid 33-byte key",
			key:     make([]byte, 33),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			block, err := newCipherBlock(tt.key)
			if (err != nil) != tt.wantErr {
				t.Errorf("newCipherBlock(key of length %d) error = %v, wantErr %v", len(tt.key), err, tt.wantErr)
			}
			if !tt.wantErr {
				if block == nil {
					t.Errorf("newCipherBlock(key of length %d) returned nil block with no error", len(tt.key))
				} else if block.BlockSize() != 16 {
					// Verify the block has the correct block size for AES (always 16 bytes)
					t.Errorf("newCipherBlock(key of length %d) block size = %d, want 16", len(tt.key), block.BlockSize())
				}
			}
			if tt.wantErr && block != nil {
				t.Errorf("newCipherBlock(key of length %d) returned non-nil block with error", len(tt.key))
			}
		})
	}
}

// TestNewCipherBlockReturnsValidCipher tests that newCipherBlock returns a functional cipher.
func TestNewCipherBlockReturnsValidCipher(t *testing.T) {
	key := make([]byte, 32) // AES-256 key
	// Fill key with sequential values to use a deterministic, non-trivial key pattern in tests.
	for i := range key {
		key[i] = byte(i)
	}

	block, err := newCipherBlock(key)
	if err != nil {
		t.Fatalf("newCipherBlock failed with valid key: %v", err)
	}

	// Test that the cipher block can encrypt and decrypt
	plaintext := []byte("0123456789abcdef") // 16 bytes (one AES block)
	ciphertext := make([]byte, len(plaintext))
	decrypted := make([]byte, len(plaintext))

	block.Encrypt(ciphertext, plaintext)
	block.Decrypt(decrypted, ciphertext)

	if string(decrypted) != string(plaintext) {
		t.Errorf("newCipherBlock cipher failed round-trip: got %x, want %x", decrypted, plaintext)
	}
}

// TestNewCipherBlockWithDifferentKeySizes tests that different key sizes produce different cipher blocks.
func TestNewCipherBlockWithDifferentKeySizes(t *testing.T) {
	keySizes := []int{16, 24, 32}
	var blocks []cipher.Block
	var ciphertexts [][]byte

	// Create a common plaintext to encrypt
	plaintext := []byte("0123456789abcdef") // 16 bytes (one AES block)

	for _, size := range keySizes {
		key := make([]byte, size)
		for i := range key {
			key[i] = byte(i)
		}
		block, err := newCipherBlock(key)
		if err != nil {
			t.Fatalf("newCipherBlock failed for %d-byte key: %v", size, err)
		}
		blocks = append(blocks, block)

		// Encrypt plaintext with this block to verify different outputs
		ciphertext := make([]byte, len(plaintext))
		block.Encrypt(ciphertext, plaintext)
		ciphertexts = append(ciphertexts, ciphertext)
	}

	// Verify all blocks are created and functional
	if len(blocks) != len(keySizes) {
		t.Errorf("Expected %d blocks, got %d", len(keySizes), len(blocks))
	}

	// All AES cipher blocks should have block size of 16 bytes
	for i, block := range blocks {
		if block.BlockSize() != 16 {
			t.Errorf("Block %d (key size %d) has block size %d, expected 16", i, keySizes[i], block.BlockSize())
		}
	}

	// Verify that different key sizes produce different ciphertext
	for i := 0; i < len(ciphertexts); i++ {
		for j := i + 1; j < len(ciphertexts); j++ {
			if bytes.Equal(ciphertexts[i], ciphertexts[j]) {
				t.Errorf("Cipher blocks with different key sizes (%d and %d bytes) produced identical ciphertext", keySizes[i], keySizes[j])
			}
		}
	}
}
