package tests

import (
	"bytes"
	"testing"

	goaes "github.com/fawwazid/go-aes"
)

func TestAESCFB_EncryptDecrypt(t *testing.T) {
	plaintext := []byte("How vexingly quick daft zebras jump")

	for _, k := range []int{16, 24, 32} {
		key := make([]byte, k)
		for i := 0; i < k; i++ {
			key[i] = byte(i)
		}

		ct, err := goaes.EncryptCFB(key, plaintext)
		if err != nil {
			t.Fatalf("encrypt failed for key len %d: %v", k, err)
		}

		pt, err := goaes.DecryptCFB(key, ct)
		if err != nil {
			t.Fatalf("decrypt failed for key len %d: %v", k, err)
		}

		if !bytes.Equal(pt, plaintext) {
			t.Fatalf("plaintext mismatch for key len %d", k)
		}

		// tamper detection: flip last byte — CFB is not authenticated,
		// so decryption will succeed but plaintext should not match original.
		bad := make([]byte, len(ct))
		copy(bad, ct)
		bad[len(bad)-1] ^= 0xFF
		pt2, err := goaes.DecryptCFB(key, bad)
		if err != nil {
			t.Fatalf("decrypt (tampered) returned error for key len %d: %v", k, err)
		}
		if bytes.Equal(pt2, plaintext) {
			t.Fatalf("expected tampered ciphertext to produce different plaintext for key len %d", k)
		}
	}
}
