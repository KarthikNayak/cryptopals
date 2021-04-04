package cryptopals

import (
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"strings"
)

func getNthLine(n int) string {
	file, _ := os.Open("_data/17.txt")
	b, _ := ioutil.ReadAll(file)
	return strings.Split(string(b), "\n")[n]
}

func pickRandomTextAndEncrypt(key []byte) ([]byte, []byte) {
	index := rand.Intn(10)
	line := getNthLine(index)

	data, _ := DecodeB64([]byte(line))

	data = PKCS7Padding(data, BlockSize)

	IV := RandomAESKey()
	blk, _ := NewAesCbc128Cipher(key, IV)

	dst := make([]byte, len(data))
	blk.Encrypt(dst, data)

	return dst, IV
}

func checkCipherTextWithPadding(key, IV, data []byte) bool {
	blk, _ := NewAesCbc128Cipher(key, IV)

	dst := make([]byte, len(data))
	blk.Decrypt(dst, data)

	lenBefore := len(dst)
	dst2 := StripPKCS7(dst)
	lenAfter := len(dst2)

	return lenAfter < lenBefore
}

func q17Recursive(checker func(data, IV []byte) bool, block, dist int, copy, final, enc []byte) bool {
	val := BlockSize - dist
	copyC0 := block*BlockSize + dist
	copyC1 := copyC0 + BlockSize
	finC1 := copyC1 - BlockSize

	for i := 0; i < 256; i++ {
		copy[copyC0] = byte(i)
		for j := copyC1 + 1; j < len(copy); j++ {
			copy[j-BlockSize] = final[j-BlockSize] ^ byte(val) ^ enc[j-BlockSize]
		}

		if checker(copy[BlockSize:], copy[:BlockSize]) {
			final[finC1] = byte(val) ^ enc[copyC0] ^ copy[copyC0]

			newDist := dist - 1
			newBlock := block
			if newDist < 0 {
				return true
			}

			if !q17Recursive(checker, newBlock, newDist, copy, final, enc) {
				continue
			} else {
				return true
			}
		}
	}

	return false
}

func SolveQ17(generator func() ([]byte, []byte), checker func(data, IV []byte) bool) {
	enc, iv := generator()
	enc2 := append(iv, enc...)
	final := make([]byte, len(enc))

	for block := len(enc)/BlockSize - 1; block >= 0; block-- {
		var copy []byte
		copy = append(copy, iv...)
		copy = append(copy, enc...)
		upperLim := (block + 2) * BlockSize

		q17Recursive(checker, block, BlockSize-1, copy[:upperLim], final, enc2[:upperLim])
	}
	fmt.Println(string(final))
}
