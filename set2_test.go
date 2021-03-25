package cryptopals

import (
	"io/ioutil"
	"strings"
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

func TestQ10(t *testing.T) {
	b64, err := ioutil.ReadFile("_data/10.txt")
	if err != nil {
		t.Errorf("error opening file: %v", err)
	}

	key := []byte("YELLOW SUBMARINE")
	iv := make([]byte, 16)

	data, err := DecodeB64(b64)
	if err != nil {
		t.Errorf("error decoding b64: %v", err)
	}

	res, err := DecryptAESCBC(data, key, iv)
	if err != nil {
		t.Errorf("error decoding aes: %v", err)
	}

	if !strings.Contains(string(res), "Play that funky music Come on, Come on, let me hear") {
		t.Fail()
	}
}

func TestRandomAESKey(t *testing.T) {
	key := RandomAESKey()
	if len(key) != BlockSize {
		t.Fail()
	}
}

func TestRandomData(t *testing.T) {
	for i := 0; i < 10; i++ {
		data := RandomText(5, 10)
		if len(data) < 5 || len(data) >= 10 {
			t.Fail()
		}
	}
}

func TestEncryptionOracle(t *testing.T) {
	src := "Hello world! This is some lorem ipsum stuff"
	dst, err := EncryptionOracle([]byte(src))
	if err != nil {
		t.Error(err)
	}

	if len(dst) == len(src) {
		t.Fail()
	}
}

func TestDetectionOracle(t *testing.T) {
	enc, err := DetectionOracle()
	if err != nil {
		t.Error(err)
	}

	if enc != CBC && enc != ECB {
		t.Fail()
	}
}

func TestQ12(t *testing.T) {
	s, err := DecryptECBConsistent()
	if err != nil {
		t.Error(err)
	}

	if !strings.Contains(s, "Rollin' in my 5.0") {
		t.Fail()
	}
}

func TestMapQueryParam(t *testing.T) {
	s := "foo=bar&baz=qux&zap=zazzle"
	m := mapQueryParam(s)

	if len(m) != 3 {
		t.Fail()
	}
	if m["foo"] != "bar" {
		t.Fail()
	}
}

func TestProfileFor(t *testing.T) {
	enc := profileFor("foo@bar.com")
	m := mapQueryParam(enc)
	if len(m) != 3 {
		t.Fail()
	}
	if m["email"] != "foo@bar.com" {
		t.Fail()
	}
}

func TestQ13(t *testing.T) {
	m := ECBCutPaste()
	if !strings.Contains(m["role"], "admin") {
		t.Fail()
	}
}

func TestFindLengthofRandomPrefix(t *testing.T) {
	unkown := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	unkownB, _ := DecodeB64([]byte(unkown))

	keyGen := RandomFixedAESKey()
	r := RandomText(1, 10)

	encryptor := func(prefix []byte) []byte {
		x, _ := ECBInconsistentOracle(r, prefix, unkownB, keyGen)
		return x
	}

	l := findLengthofRandomPrefix(encryptor)
	if l != len(r) {
		t.Fatalf("wanted length: %v got %v", len(r), l)
	}
}

func TestQ14(t *testing.T) {
	s, err := DecryptECBInconsistent()
	if err != nil {
		t.Error(err)
	}

	if !strings.Contains(s, "Rollin' in my 5.0") {
		t.Fail()
	}
}
