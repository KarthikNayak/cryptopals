package cryptopals

import (
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
