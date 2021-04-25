package cryptopals

import (
	"strings"
	"testing"
)

func TestQ17(t *testing.T) {
	key := RandomAESKey()

	generator := func() ([]byte, []byte) {
		return pickRandomTextAndEncrypt(key)
	}
	checker := func(data, IV []byte) bool {
		return checkCipherTextWithPadding(key, IV, data)
	}

	SolveQ17(generator, checker)
}

func TestQ18(t *testing.T) {
	data := "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="
	input, _ := DecodeB64([]byte(data))
	a, _ := NewAesCtrCipher([]byte("YELLOW SUBMARINE"), 0)

	dst := make([]byte, len(input))
	a.Decrypt(dst, input)

	if !strings.Contains(string(dst), "baby Ice, Ice") {
		t.Fail()
	}
}
