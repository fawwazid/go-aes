package goaes_test

import (
	"bytes"
	"testing"

	goaes "github.com/fawwazid/go-aes"
)

func TestAESCBC_EncryptDecrypt(t *testing.T) {
	plaintext := []byte("Sphinx of black quartz, judge my vow")

	for _, k := range []int{16, 24, 32} {
		key := make([]byte, k)
		for i := 0; i < k; i++ {
			key[i] = byte(i)
		}

		ct, err := goaes.EncryptCBC(key, plaintext)
		if err != nil {
			t.Fatalf("encrypt failed for key len %d: %v", k, err)
		}

		pt, err := goaes.DecryptCBC(key, ct)
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
		_, err = goaes.DecryptCBC(key, bad)
		if err == nil {
			t.Fatalf("expected decryption error for tampered ciphertext (key len %d)", k)
		}
	}
}
func TestAESCBC_InvalidKey(t *testing.T) {
	key := []byte("invalid-key") // 11 bytes
	plaintext := []byte("secret")

	_, err := goaes.EncryptCBC(key, plaintext)
	if err == nil {
		t.Error("expected error for invalid key size in EncryptCBC")
	}

	_, err = goaes.DecryptCBC(key, []byte("iv-and-ct-that-is-too-short"))
	if err == nil {
		t.Error("expected error for invalid key size in DecryptCBC")
	}
}
