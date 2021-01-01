package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"log"
)

func hexToB64(src []byte) ([]byte, error) {
	b := make([]byte, hex.DecodedLen(len(src)))
	_, err := hex.Decode(b, src)
	if err != nil {
		return b, err
	}

	log.Println(string(b))

	dst := make([]byte, base64.StdEncoding.EncodedLen(len(b)))

	base64.StdEncoding.Encode(dst, b)

	return dst, nil
}
