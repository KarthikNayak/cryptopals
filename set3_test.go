package cryptopals

import (
	"bufio"
	"fmt"
	"os"
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

func TestQ19(t *testing.T) {
	f, _ := os.Open("_data/19.txt")
	defer f.Close()

	var data [][]byte

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line, _ := DecodeB64(scanner.Bytes())
		data = append(data, line)
	}

	SolveQ19(data)
}

func TestQ20(t *testing.T) {
	f, _ := os.Open("_data/20.txt")
	defer f.Close()

	var data [][]byte

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line, _ := DecodeB64(scanner.Bytes())
		data = append(data, line)
	}

	SolveQ20(data)
}

func TestQ21(t *testing.T) {
	seed, extract := MT19937()

	seed(123)
	x, err := extract()
	if err != nil {
		t.Fatalf(err.Error())
	}
	fmt.Println(x)
}
