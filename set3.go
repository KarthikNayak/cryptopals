package cryptopals

import (
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"strconv"
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

func solveDigits(data []byte) byte {
	ans := 0
	maxVal := 0
	for i := 0; i < 256; i++ {
		res := 0
		for _, val := range data {
			x := val ^ byte(i)
			cf, ok := charFrequency[x]
			if !ok {
				cf = -1
			}
			res += cf
		}
		if res > maxVal {
			ans = i
			maxVal = res
		}
	}
	return byte(ans)
}

func SolveQ19(src [][]byte) {
	nonce := 0
	key := RandomAESKey()

	ctr, _ := NewAesCtrCipher(key, int64(nonce))
	enc := make([][]byte, len(src))

	ciphLen := 0
	for i, s := range src {
		d := make([]byte, len(s))
		ctr.Encrypt(d, s)
		enc[i] = d
		if len(d) > ciphLen {
			ciphLen = len(d)
		}
	}

	ciph := make([]byte, ciphLen)

	for i := 0; i < len(ciph); i++ {
		bits := make([]byte, 0)
		for _, s := range enc {
			if len(s) > i {
				bits = append(bits, s[i])
			}
		}
		ciph[i] = solveDigits(bits)
	}

	for _, s := range enc {
		for i, bit := range s {
			fmt.Printf("%s", string(bit^ciph[i]))
		}
		fmt.Println()
	}
}

func SolveQ20(src [][]byte) {
	minLen := len(src[0])

	for _, str := range src {
		if len(str) < minLen {
			minLen = len(str)
		}
	}

	var data []byte

	for _, str := range src {
		data = append(data, str[:minLen]...)
	}

	keySize := 16
	blocks := breakIntoBlocks(data, keySize)
	key := make([]byte, keySize)

	for i := 0; i < keySize; i++ {
		key[i], _, _ = SingleByteXorKeyRaw(blocks[i])
	}

	for i := 0; i < len(data); i++ {
		if i%keySize == 0 {
			fmt.Println()
		}
		fmt.Printf("%s", string(data[i]^key[i%keySize]))
	}
}

func MT19937() (func(seed uint32), func() (uint32, error)) {
	w, n, m, r := uint32(32), uint32(624), uint32(397), uint32(31)
	a, _ := strconv.ParseUint("9908B0DF", 16, 32)
	u := uint32(11)
	d, _ := strconv.ParseUint("FFFFFFFF", 16, 32)
	s := uint32(7)
	b, _ := strconv.ParseUint("9D2C5680", 16, 32)
	t := uint32(15)
	c, _ := strconv.ParseUint("EFC60000", 16, 32)
	l := uint32(18)
	f := uint32(1812433253)

	mt := make([]uint32, n)
	index := uint32(n + 1)

	lowerMask := uint32((1 << r) - 1)
	upperMask := uint32(^lowerMask) & 0xFFFFFFFF

	seed := func(seed uint32) {
		index = n
		mt[0] = seed
		for i := uint32(1); i < (n - 1); i++ {
			mt[i] = (f*((mt[i-1])^((mt[i-1])>>(w-2))) + i) & 0xFFFFFFFF
		}
	}

	twist := func() {
		for i := uint32(0); i < n; i++ {
			x := (mt[i] & upperMask) + (mt[(i+1)%n] & lowerMask)
			xA := x >> 1
			if (x % 2) != 0 {
				xA = xA ^ uint32(a)
			}
			mt[i] = mt[(i+m)%n] ^ xA
		}
		index = 0
	}

	extract := func() (uint32, error) {
		if index >= n {
			if index > n {
				return 0, errors.New("no seed")
			}
			twist()
		}

		y := uint32(mt[index])
		y = y ^ ((y >> u) & uint32(d))
		y = y ^ ((y << s) & uint32(b))
		y = y ^ ((y << t) & uint32(c))
		y = y ^ (y >> l)

		index = index + 1
		return (y & 0xFFFFFFFF), nil
	}

	return seed, extract
}
