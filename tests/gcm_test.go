package tests

import (
	"bytes"
	"testing"

	goaes "github.com/fawwazid/go-aes"
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
