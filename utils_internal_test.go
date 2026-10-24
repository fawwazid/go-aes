package goaes

import "testing"

func TestValidateKeySizeLength(t *testing.T) {
	for _, length := range []int{-1, 0, 15, 16, 17, 23, 24, 25, 31, 32, 33, 64} {
		valid := length == 16 || length == 24 || length == 32
		if err := validateKeySizeLength(length); (err == nil) != valid {
			t.Errorf("key length %d: %v", length, err)
		}
	}
}

func TestValidateXTSKeySize(t *testing.T) {
	for _, length := range []int{0, 16, 24, 31, 32, 33, 48, 64, 65, 128} {
		key := make([]byte, length)
		if length > 0 {
			key[length-1] = 1
		}
		valid := length == 32 || length == 64
		if err := validateXTSKeySize(key); (err == nil) != valid {
			t.Errorf("XTS key length %d: %v", length, err)
		}
	}
	for _, length := range []int{32, 64} {
		if err := validateXTSKeySize(make([]byte, length)); err == nil {
			t.Errorf("accepted identical XTS key halves: %d bytes", length)
		}
	}
}
