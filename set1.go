package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"log"
)

func DecodeHex(src []byte) ([]byte, error) {
	b := make([]byte, hex.DecodedLen(len(src)))
	_, err := hex.Decode(b, src)

	return b, err
}

func hexToB64(src []byte) ([]byte, error) {
	b, err := DecodeHex(src)
	if err != nil {
		return b, err
	}

	log.Println(string(b))

	dst := make([]byte, base64.StdEncoding.EncodedLen(len(b)))

	base64.StdEncoding.Encode(dst, b)

	return dst, nil
}

func Xor(a, b []byte) ([]byte, error) {
	aByte, err := DecodeHex(a)
	if err != nil {
		return aByte, err
	}
	bByte, err := DecodeHex(b)
	if err != nil {
		return bByte, err
	}

	log.Println(string(a))
	log.Println(string(b))

	c := make([]byte, len(aByte))
	for i := 0; i < len(c); i++ {
		c[i] = aByte[i] ^ bByte[i]
	}

	dst := make([]byte, hex.EncodedLen(len(c)))
	hex.Encode(dst, c)

	return dst, nil
}
