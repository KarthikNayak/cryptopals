package cryptopals

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"math/bits"
	"sort"
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

func DecodeB64(src []byte) ([]byte, error) {
	b := make([]byte, base64.StdEncoding.DecodedLen(len(src)))
	_, err := base64.StdEncoding.Decode(b, src)
	return b, err
}

func HexToB64(src []byte) ([]byte, error) {
	b, err := DecodeHex(src)
	if err != nil {
		return b, err
	}

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
		val, ok := charFrequency[s[i]]
		if !ok {
			val = -1
		}
		sum = sum + val
	}
	return sum
}

func SingleByteXorKeyRaw(src []byte) (byte, int, string) {
	dst := make([]byte, len(src))
	maxString := ""
	maxVal := 0
	maxKey := 0

	for key := 0; key < 256; key++ {
		for i := 0; i < len(dst); i++ {
			dst[i] = src[i] ^ byte(key)
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

func SingleByteXorKey(hex []byte) (byte, int, string) {
	b, _ := DecodeHex(hex)
	return SingleByteXorKeyRaw(b)
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

func HammingDistance(a, b []byte) int {
	dist := 0

	for i := range a {
		val := a[i] ^ b[i]
		dist = dist + bits.OnesCount(uint(val))
	}

	return dist
}

func findLowKeySize(data []byte, size int) []int {
	type kv struct {
		Key   int
		Value float64
	}

	var ss []kv

	for keySize := 2; keySize <= 40; keySize++ {
		val := 0.0
		for i := 0; i < 10; i++ {
			d1, d2 := data[keySize*i:keySize*(i+1)], data[keySize*(i+1):keySize*(i+2)]
			val = val + float64(HammingDistance(d1, d2))/float64(keySize)
		}
		val = val / 5

		ss = append(ss, kv{keySize, val})
	}

	sort.Slice(ss, func(i, j int) bool {
		return ss[i].Value < ss[j].Value
	})

	val := make([]int, size)
	for i := range val {
		val[i] = int(ss[i].Key)
	}
	return val
}

func breakIntoBlocks(src []byte, size int) [][]byte {
	dst := make([][]byte, size)

	for i := 0; i < size; i++ {
		dst[i] = []byte{}
	}

	for i := range src {
		dst[i%size] = append(dst[i%size], src[i])
	}

	return dst
}

func BreakRepeatingXor(src []byte) ([]byte, error) {
	data, err := DecodeB64(src)
	if err != nil {
		return []byte{}, err
	}

	keySizes := findLowKeySize(data, 1)

	for _, keySize := range keySizes {
		blocks := breakIntoBlocks(data, keySize)
		key := make([]byte, keySize)

		for i := 0; i < keySize; i++ {
			key[i], _, _ = SingleByteXorKeyRaw(blocks[i])
		}
		return key, nil
	}

	return []byte{}, nil
}

func DecrpytAESECB(src, key []byte) ([]byte, error) {
	blk, err := NewAesEcb128Cipher(key)
	if err != nil {
		return []byte{}, err
	}

	dst := make([]byte, len(src))
	blk.Decrypt(dst, src)

	return dst, nil
}

func DetectAESECB(data []byte) bool {
	for i := 0; i < len(data); i = i + 16 {
		for j := i + 16; j < len(data); j = j + 16 {
			if bytes.Compare(data[i:i+16], data[j:j+16]) == 0 {
				return true
			}
		}
	}
	return false
}
