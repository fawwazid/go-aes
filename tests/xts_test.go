package tests

import (
	"bytes"
	"testing"

	goaes "github.com/fawwazid/go-aes"
)

func TestAESXTS_EncryptDecrypt(t *testing.T) {
	// 4 blocks = 64 bytes (multiple of 16)
	plaintext := bytes.Repeat([]byte("1234567890ABCDEF"), 4)

	for _, totalKey := range [][]byte{
		// 32 bytes -> AES-128 XTS (two 16-byte keys)
		func() []byte {
			k := make([]byte, 32)
			for i := 0; i < 32; i++ {
				k[i] = byte(i)
			}
			return k
		}(),
		// 48 bytes -> AES-192 XTS
		func() []byte {
			k := make([]byte, 48)
			for i := 0; i < 48; i++ {
				k[i] = byte(i)
			}
			return k
		}(),
		// 64 bytes -> AES-256 XTS
		func() []byte {
			k := make([]byte, 64)
			for i := 0; i < 64; i++ {
				k[i] = byte(i)
			}
			return k
		}(),
	} {
		ct, err := goaes.EncryptXTS(totalKey, plaintext, 42)
		if err != nil {
			t.Fatalf("encrypt failed for key len %d: %v", len(totalKey), err)
		}

		pt, err := goaes.DecryptXTS(totalKey, ct, 42)
		if err != nil {
			t.Fatalf("decrypt failed for key len %d: %v", len(totalKey), err)
		}

		if !bytes.Equal(pt, plaintext) {
			t.Fatalf("plaintext mismatch for key len %d", len(totalKey))
		}

		// Tampering: flip last byte — XTS is unauthenticated so decryption will succeed
		bad := make([]byte, len(ct))
		copy(bad, ct)
		bad[len(bad)-1] ^= 0xFF
		pt2, err := goaes.DecryptXTS(totalKey, bad, 42)
		if err != nil {
			t.Fatalf("decrypt (tampered) returned error for key len %d: %v", len(totalKey), err)
		}
		if bytes.Equal(pt2, plaintext) {
			t.Fatalf("expected tampered ciphertext to produce different plaintext for key len %d", len(totalKey))
		}
	}
}
