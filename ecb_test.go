package goaes_test

import (
	"bytes"
	"testing"

	goaes "github.com/fawwazid/go-aes"
)

func TestAESECB_EncryptDecrypt(t *testing.T) {
	plaintext := []byte("Pack my box with five dozen liquor jugs")

	for _, k := range []int{16, 24, 32} {
		key := make([]byte, k)
		for i := 0; i < k; i++ {
			key[i] = byte(i)
		}

		ct, err := goaes.EncryptECB(key, plaintext)
		if err != nil {
			t.Fatalf("encrypt failed for key len %d: %v", k, err)
		}

		pt, err := goaes.DecryptECB(key, ct)
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
		_, err = goaes.DecryptECB(key, bad)
		if err == nil {
			t.Fatalf("expected decryption error for tampered ciphertext (key len %d)", k)
		}
	}
}
