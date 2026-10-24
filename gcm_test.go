package goaes_test

import (
	"bytes"
	"encoding/hex"
	"testing"

	goaes "github.com/fawwazid/go-aes/v2"
)

func TestAESGCM_EncryptDecrypt(t *testing.T) {
	plaintext := []byte("The quick brown fox jumps over the lazy dog")
	aad := []byte("header-aad")

	for _, k := range []int{16, 24, 32} {
		key := make([]byte, k)
		for i := 0; i < k; i++ {
			key[i] = byte(i)
		}

		ct, err := goaes.EncryptGCM(key, plaintext, aad)
		if err != nil {
			t.Fatalf("encrypt failed for key len %d: %v", k, err)
		}

		pt, err := goaes.DecryptGCM(key, ct, aad)
		if err != nil {
			t.Fatalf("decrypt failed for key len %d: %v", k, err)
		}

		if !bytes.Equal(pt, plaintext) {
			t.Fatalf("plaintext mismatch for key len %d", k)
		}

		// tamper detection: flip last byte
		bad := make([]byte, len(ct))
		copy(bad, ct)
		bad[len(bad)-1] ^= 0xFF
		_, err = goaes.DecryptGCM(key, bad, aad)
		if err == nil {
			t.Fatalf("expected decryption error for tampered ciphertext (key len %d)", k)
		}
	}
}

// TestAESGCM_NISTKnownAnswer checks a vector from NIST SP 800-38D, Test Case 2.
func TestAESGCM_NISTKnownAnswer(t *testing.T) {
	decode := func(s string) []byte {
		b, err := hex.DecodeString(s)
		if err != nil {
			t.Fatal(err)
		}
		return b
	}

	key := make([]byte, 16)
	nonce := make([]byte, 12)
	ciphertextAndTag := decode("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf")
	input := append(nonce, ciphertextAndTag...)

	plaintext, err := goaes.DecryptGCM(key, input, nil)
	if err != nil {
		t.Fatalf("DecryptGCM failed NIST known-answer test: %v", err)
	}
	if !bytes.Equal(plaintext, make([]byte, 16)) {
		t.Fatalf("DecryptGCM plaintext = %x, want 16 zero bytes", plaintext)
	}
}
func TestAESGCM_InvalidKey(t *testing.T) {
	key := []byte("invalid-key") // 11 bytes
	plaintext := []byte("secret")

	_, err := goaes.EncryptGCM(key, plaintext, nil)
	if err == nil {
		t.Error("expected error for invalid key size in EncryptGCM")
	}

	_, err = goaes.DecryptGCM(key, []byte("ct"), nil)
	if err == nil {
		t.Error("expected error for invalid key size in DecryptGCM")
	}
}
