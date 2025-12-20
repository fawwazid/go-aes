package goaes_test

import (
	"testing"

	goaes "github.com/fawwazid/go-aes"
)

func TestGenerateAESKey(t *testing.T) {
	tests := []struct {
		bits    int
		wantErr bool
	}{
		{128, false},
		{192, false},
		{256, false},
		{127, true},
		{255, true},
		{0, true},
	}

	for _, tt := range tests {
		key, err := goaes.GenerateAESKey(tt.bits)
		if (err != nil) != tt.wantErr {
			t.Errorf("GenerateAESKey(%d) error = %v, wantErr %v", tt.bits, err, tt.wantErr)
			continue
		}
		if !tt.wantErr {
			if len(key) != tt.bits/8 {
				t.Errorf("GenerateAESKey(%d) key length = %d, want %d", tt.bits, len(key), tt.bits/8)
			}
		}
	}
}

func TestGenerateNonce(t *testing.T) {
	tests := []struct {
		size    int
		wantLen int
	}{
		{0, 12}, // Default GCM size
		{12, 12},
		{16, 16},
	}

	for _, tt := range tests {
		nonce, err := goaes.GenerateNonce(tt.size)
		if err != nil {
			t.Errorf("GenerateNonce(%d) error = %v", tt.size, err)
			continue
		}
		if len(nonce) != tt.wantLen {
			t.Errorf("GenerateNonce(%d) length = %d, want %d", tt.size, len(nonce), tt.wantLen)
		}
	}

	_, err := goaes.GenerateNonce(-1)
	if err == nil {
		t.Error("GenerateNonce(-1) expected error, got nil")
	}
}

func TestBase64Helpers(t *testing.T) {
	data := []byte("hello world")
	encoded := goaes.EncodeBase64(data)
	decoded, err := goaes.DecodeBase64(encoded)
	if err != nil {
		t.Fatalf("DecodeBase64 failed: %v", err)
	}
	if string(decoded) != string(data) {
		t.Errorf("Base64 mismatch: got %s, want %s", string(decoded), string(data))
	}
}

func TestHexHelpers(t *testing.T) {
	data := []byte("hello world")
	encoded := goaes.HexEncode(data)
	decoded, err := goaes.HexDecode(encoded)
	if err != nil {
		t.Fatalf("HexDecode failed: %v", err)
	}
	if string(decoded) != string(data) {
		t.Errorf("Hex mismatch: got %s, want %s", string(decoded), string(data))
	}
}
