package cryptopals

import (
	"io/ioutil"
	"log"
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

	log.Println(len(data), len(data)/16, len(data)%16)

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
