package cryptopals

import (
	"encoding/base64"
	"encoding/hex"
	"log"
	"strings"
)

var (
	// taken from https://opendata.stackexchange.com/questions/7042/ascii-character-frequency-analysis
	charFrequency = map[byte]int{
		' ': 67,
		',': 4,
		'.': 4,
		'E': 1,
		'D': 1,
		'L': 1,
		'U': 1,
		'a': 29,
		'c': 16,
		'b': 3,
		'e': 37,
		'd': 18,
		'g': 3,
		'f': 3,
		'i': 42,
		'h': 1,
		'm': 17,
		'l': 21,
		'o': 29,
		'n': 24,
		'q': 5,
		'p': 11,
		's': 18,
		'r': 22,
		'u': 28,
		't': 32,
		'v': 3,
		'x': 3,
	}
)

func DecodeHex(src []byte) ([]byte, error) {
	b := make([]byte, hex.DecodedLen(len(src)))
	_, err := hex.Decode(b, src)

	return b, err
}

func EncodeHex(src []byte) []byte {
	b := make([]byte, hex.EncodedLen(len(src)))
	hex.Encode(b, src)

	return b
}

func HexToB64(src []byte) ([]byte, error) {
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

	log.Println(string(aByte))
	log.Println(string(bByte))

	c := make([]byte, len(aByte))
	for i := 0; i < len(c); i++ {
		c[i] = aByte[i] ^ bByte[i]
	}

	dst := make([]byte, hex.EncodedLen(len(c)))
	hex.Encode(dst, c)

	return dst, nil
}

func CharacterFrequency(s []byte) int {
	var sum int
	s = []byte(strings.ToLower(string(s)))

	for i := 0; i < len(s); i++ {
		sum = sum + charFrequency[s[i]]
	}
	return sum
}

func SingleByteXorKey(hex []byte) (byte, int, string) {
	b, _ := DecodeHex(hex)
	dst := make([]byte, len(b))

	maxString := ""
	maxVal := 0
	maxKey := 0

	for key := 0; key < 256; key++ {
		for i := 0; i < len(dst); i++ {
			dst[i] = b[i] ^ byte(key)
		}
		val := CharacterFrequency(dst)
		if val > maxVal {
			maxString = string(dst)
			maxVal = val
			maxKey = key
		}
	}

	return byte(maxKey), maxVal, maxString
}

func MultipleSingleByteXorKey(list []string) string {
	maxVal, maxString := 0, ""
	for _, hex := range list {
		_, val, s := SingleByteXorKey([]byte(hex))
		if val > maxVal {
			maxVal = val
			maxString = s
		}
	}
	return maxString
}

func RepeatingXor(s string, key string) []byte {
	b := make([]byte, len(s))

	for i := range s {
		b[i] = s[i] ^ key[i%len(key)]
	}

	return EncodeHex(b)
}
