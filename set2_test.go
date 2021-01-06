package cryptopals

import (
	"testing"
)

func TestQ9(t *testing.T) {
	src := "YELLOW SUBMARINE"
	dst := PKCS7Padding([]byte(src), 20)

	for i := 16; i < 20; i++ {
		if dst[i] != byte(4) {
			t.Fail()
		}
	}
}
