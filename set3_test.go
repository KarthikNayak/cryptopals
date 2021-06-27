package cryptopals

import (
	"bufio"
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
	_, err := extract()
	if err != nil {
		t.Fatalf(err.Error())
	}
}

func TestQ22CheckSeedValues(t *testing.T) {
	seed1, extract1 := MT19937()
	seed2, extract2 := MT19937()
	seed3, extract3 := MT19937()

	seed1(6789)
	seed2(6789)
	seed3(6798)

	x1, err := extract1()
	if err != nil {
		t.Fatalf(err.Error())
	}

	x2, err := extract2()
	if err != nil {
		t.Fatalf(err.Error())
	}

	x3, err := extract3()
	if err != nil {
		t.Fatalf(err.Error())
	}

	if x1 != x2 {
		t.Fatal("same seed but different output")
	}

	if x2 == x3 {
		t.Fatal("diff seed but same output")
	}
}

func TestQ22(t *testing.T) {
	err := SolveMT19937Seed()
	if err != nil {
		t.Fatal(err)
	}
}
