package goaes

import (
	"bytes"
	"crypto/fips140"
	"errors"
	"testing"
)

func TestFIPSPolicy(t *testing.T) {
	if !fips140.Enabled() {
		t.Skip("requires FIPS mode")
	}
	key := make([]byte, 32)
	if _, err := EncryptXTS(key, nil, 0); !errors.Is(err, ErrFIPSUnsupported) {
		t.Fatal(err)
	}
	if _, err := DecryptXTS(key, nil, 0); !errors.Is(err, ErrFIPSUnsupported) {
		t.Fatal(err)
	}
	plaintext, aad := []byte("FIPS GCM round trip"), []byte("context")
	ciphertext, err := EncryptGCM(key, plaintext, aad)
	if err != nil {
		t.Fatal(err)
	}
	if len(ciphertext) != len(plaintext)+28 {
		t.Fatal("invalid ciphertext envelope")
	}
	got, err := DecryptGCM(key, ciphertext, aad)
	if err != nil || !bytes.Equal(got, plaintext) {
		t.Fatalf("decrypt=%q,%v", got, err)
	}
	if got, err := DecryptGCM(key, ciphertext, []byte("wrong")); err == nil || got != nil {
		t.Fatal("accepted wrong AAD")
	}
}
