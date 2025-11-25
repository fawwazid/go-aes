package tests

import (
	"bytes"
	"testing"

	goaes "github.com/fawwazid/go-aes"
)

func TestAESOFB_EncryptDecrypt(t *testing.T) {
	plaintext := []byte("Bright vixens jump; dozy fowl quack")

	for _, k := range []int{16, 24, 32} {
		key := make([]byte, k)
		for i := 0; i < k; i++ {
			key[i] = byte(i)
		}

		ct, err := goaes.EncryptOFB(key, plaintext)
		if err != nil {
			t.Fatalf("encrypt failed for key len %d: %v", k, err)
		}

		pt, err := goaes.DecryptOFB(key, ct)
		if err != nil {
			t.Fatalf("decrypt failed for key len %d: %v", k, err)
		}

		if !bytes.Equal(pt, plaintext) {
			t.Fatalf("plaintext mismatch for key len %d", k)
		}

		// tamper detection: flip last byte — OFB is unauthenticated,
		// so decryption will succeed but plaintext should differ.
		bad := make([]byte, len(ct))
		copy(bad, ct)
		bad[len(bad)-1] ^= 0xFF
		pt2, err := goaes.DecryptOFB(key, bad)
		if err != nil {
			t.Fatalf("decrypt (tampered) returned error for key len %d: %v", k, err)
		}
		if bytes.Equal(pt2, plaintext) {
			t.Fatalf("expected tampered ciphertext to produce different plaintext for key len %d", k)
		}
	}
}
