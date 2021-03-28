package cryptopals

import (
	"bytes"
	"crypto/cipher"
	"fmt"
	"math/rand"
	"strings"
	"time"
)

const (
	ECB = 1
	CBC = 2
)

func init() {
	rand.Seed(time.Now().Unix())
}

func PKCS7Padding(src []byte, blockLength int) []byte {
	padLen := blockLength - (len(src) % blockLength)
	if padLen == blockLength {
		return src
	}

	dst := make([]byte, len(src)+padLen)

	copy(dst, src)
	for i := len(src); i < len(src)+padLen; i++ {
		dst[i] = byte(padLen)
	}

	return dst
}

func DecryptAESCBC(src, key, iv []byte) ([]byte, error) {
	blk, err := NewAesCbc128Cipher(key, iv)
	if err != nil {
		return []byte{}, err
	}

	dst := make([]byte, len(src))
	blk.Decrypt(dst, src)

	return dst, nil
}

func RandomAESKey() []byte {
	dst := make([]byte, BlockSize)
	rand.Read(dst)

	return dst
}

func RandomFixedAESKey() func() []byte {
	dst := make([]byte, BlockSize)
	rand.Read(dst)

	return func() []byte {
		return dst
	}
}

func RandomText(start, end int) []byte {
	var size int = start
	if end != start {
		size = start + rand.Intn(end-start)
	}

	data := make([]byte, size)
	rand.Read(data)
	return data
}

func EncryptionOracle(src []byte) ([]byte, error) {
	prefix := RandomText(5, 10)
	src = append(prefix, src...)
	src = PKCS7Padding([]byte(src), BlockSize)

	key := RandomAESKey()

	decider := rand.Intn(2)

	var err error
	var blk cipher.Block

	if decider == 0 {
		iv := RandomAESKey()
		blk, err = NewAesCbc128Cipher(key, iv)
	} else {
		blk, err = NewAesEcb128Cipher(key)
	}

	if err != nil {
		return []byte{}, err
	}

	dst := make([]byte, len(src))
	blk.Encrypt(dst, src)

	return dst, nil
}

func DetectionOracle() (int, error) {
	data := make([]byte, BlockSize*20)
	magicNum := 5
	for i := 0; i < len(data); i++ {
		data[i] = byte(magicNum)
	}

	dst, err := EncryptionOracle(data)
	if err != nil {
		return 0, err
	}

	if bytes.Compare(dst[5*BlockSize:6*BlockSize], dst[6*BlockSize:7*BlockSize]) == 0 {
		return ECB, nil
	}
	return CBC, nil
}

func ECBConsistentOracle(prefix, src []byte, keyGen func() []byte) ([]byte, error) {
	src = append(prefix, src...)
	src = PKCS7Padding([]byte(src), BlockSize)

	key := keyGen()

	var err error
	var blk cipher.Block

	blk, err = NewAesEcb128Cipher(key)

	if err != nil {
		return []byte{}, err
	}

	dst := make([]byte, len(src))
	blk.Encrypt(dst, src)

	return dst, nil
}

func DetectECBBlockSize(encrypt func([]byte) []byte) int {
	for size := 1; ; size++ {
		data := make([]byte, size*2)
		for i := 0; i < len(data); i++ {
			data[i] = byte('A')
		}
		enc := encrypt(data)
		if bytes.Compare(enc[0:size], enc[size:2*size]) == 0 {
			return size
		}
	}
}

func DecryptECBConsistent() (string, error) {
	unkown := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	unkownB, err := DecodeB64([]byte(unkown))

	if err != nil {
		return "", err
	}

	keyGen := RandomFixedAESKey()

	encryptor := func(prefix []byte) []byte {
		x, _ := ECBConsistentOracle(prefix, unkownB, keyGen)
		return x
	}

	blockSize := DetectECBBlockSize(encryptor)

	totalSize := encryptor([]byte{})

	final := make([]byte, 0)

	for i := 0; i < len(totalSize); i++ {
		x := make([]byte, blockSize-(i%blockSize)-1)
		for j := 0; j < len(x); j++ {
			x[j] = byte('A')
		}

		output := encryptor(x)
		x = append(x, final...)

		blockToCmp := i / blockSize
		startIndex := blockSize * blockToCmp
		endIndex := startIndex + blockSize

		for j := 0; j < 256; j++ {
			val := append(x, byte(j))
			cmp := encryptor(val)

			if bytes.Compare(output[startIndex:endIndex], cmp[startIndex:endIndex]) == 0 {
				final = append(final, byte(j))
				break
			}
		}
	}
	return string(final), nil
}

func mapQueryParam(query string) map[string]string {
	m := make(map[string]string)
	for _, pair := range strings.Split(query, "&") {
		keyVal := strings.Split(pair, "=")
		m[keyVal[0]] = keyVal[1]
	}
	return m
}

func profileFor(email string) string {
	email = strings.ReplaceAll(email, "&", "")
	email = strings.ReplaceAll(email, "=", "")

	return fmt.Sprintf("email=%s&uid=%s&role=%s", email, "10", "user")
}

func encryptUserProfile(profile string, key []byte) []byte {
	blk, _ := NewAesEcb128Cipher(key)

	src := PKCS7Padding([]byte(profile), BlockSize)

	dst := make([]byte, len(src))
	blk.Encrypt(dst, []byte(src))

	return dst
}

func decryptUserProfile(encryptedData, key []byte) map[string]string {
	blk, _ := NewAesEcb128Cipher(key)

	dst := make([]byte, len(encryptedData))
	blk.Decrypt(dst, []byte(encryptedData))

	return mapQueryParam(string(dst))
}

func ECBCutPaste() map[string]string {
	key := RandomAESKey()

	s := profileFor("")
	size := len(s)
	extra := BlockSize - (size-4)%BlockSize
	x := make([]byte, extra)
	for i := 0; i < len(x); i++ {
		x[i] = 'a'
	}

	s = profileFor(string(x))
	b1 := encryptUserProfile(s, key)

	botchedEmail := []byte("aaaaaaaaaaadmin")
	for i := 0; i < len(x); i++ {
		botchedEmail = append(botchedEmail, 0)
	}

	extra = BlockSize - (size+len(botchedEmail)-4)%BlockSize
	x = make([]byte, extra)
	for i := 0; i < len(x); i++ {
		x[i] = 'a'
	}
	x = append([]byte(botchedEmail), x...)

	s = profileFor(string(x))
	b2 := encryptUserProfile(s, key)

	startB1 := len(b1) - BlockSize
	for i := 0; i < 16; i++ {
		b1[startB1+i] = b2[16+i]
	}

	return decryptUserProfile(b1, key)
}

func ECBInconsistentOracle(r, prefix, src []byte, keyGen func() []byte) ([]byte, error) {
	src = append(prefix, src...)
	src = append(r, src...)
	src = PKCS7Padding([]byte(src), BlockSize)

	key := keyGen()

	var err error
	var blk cipher.Block

	blk, err = NewAesEcb128Cipher(key)

	if err != nil {
		return []byte{}, err
	}

	dst := make([]byte, len(src))
	blk.Encrypt(dst, src)

	return dst, nil
}

func findLengthofRandomPrefix(encryptor func(prefix []byte) []byte) int {
	x := []byte{}
	for i := 0; i < BlockSize*2; i++ {
		x = append(x, 'A')
	}

	for i := 1; i < BlockSize; i++ {
		x = append(x, 'A')
		data := encryptor(x)
		if bytes.Compare(data[BlockSize:BlockSize*2], data[BlockSize*2:BlockSize*3]) == 0 {
			return BlockSize - i
		}
	}
	return 0
}

func DecryptECBInconsistent() (string, error) {
	unkown := "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"
	unkownB, err := DecodeB64([]byte(unkown))

	if err != nil {
		return "", err
	}

	keyGen := RandomFixedAESKey()
	r := RandomText(4, 10)

	encryptor := func(prefix []byte) []byte {
		x, _ := ECBInconsistentOracle(r, prefix, unkownB, keyGen)
		return x
	}

	blockSize := BlockSize

	randomSize := findLengthofRandomPrefix(encryptor)
	filler := []byte{}
	for i := 0; i < BlockSize-randomSize; i++ {
		filler = append(filler, 'A')
	}

	totalSize := encryptor([]byte{})
	final := make([]byte, 0)

	for i := 0; i < len(totalSize); i++ {
		x := make([]byte, blockSize-(i%blockSize)-1)
		for j := 0; j < len(x); j++ {
			x[j] = byte('A')
		}
		x = append(filler, x...)

		output := encryptor(x)
		output = output[BlockSize:]
		x = append(x, final...)

		blockToCmp := (i / blockSize)
		startIndex := blockSize * blockToCmp
		endIndex := startIndex + blockSize

		for j := 0; j < 256; j++ {
			val := append(x, byte(j))
			cmp := encryptor(val)
			cmp = cmp[BlockSize:]

			if bytes.Compare(output[startIndex:endIndex], cmp[startIndex:endIndex]) == 0 {
				final = append(final, byte(j))
				break
			}
		}
		fmt.Println(string(final))
	}
	return string(final), nil
}

func StripPKCS7(data []byte) []byte {
	padSize := data[len(data)-1]

	valid := true
	if padSize == 0 {
		valid = false
	}

	for i := len(data) - int(padSize); i < len(data); i++ {
		if data[i] != padSize {
			valid = false
			break
		}
	}

	if valid {
		return data[:len(data)-int(padSize)]
	}
	return data
}

func CombineUserData(input, key, iv []byte) []byte {
	prefix := "comment1=cooking%20MCs;userdata="
	postfix := ";comment2=%20like%20a%20pound%20of%20bacon"

	var data []byte

	data = append(data, []byte(prefix)...)

	for _, val := range input {
		if val == byte(';') {
			data = append(data, "\";\""...)
		} else if val == byte('=') {
			data = append(data, "\"=\""...)
		} else {
			data = append(data, val)
		}
	}

	data = append(data, postfix...)
	data = PKCS7Padding(data, BlockSize)

	blk, _ := NewAesCbc128Cipher(key, iv)
	dst := make([]byte, len(data))
	blk.Encrypt(dst, data)

	return dst
}

func CheckForCBCAdmin(key, iv, src []byte) bool {
	blk, _ := NewAesCbc128Cipher(key, iv)
	dst := make([]byte, len(src))
	blk.Decrypt(dst, src)

	return strings.Contains(string(dst), ";admin=true;")
}

func CBCBitFlipping(checker func(data []byte) bool, encryptor func(src []byte) []byte) bool {
	prefixLength := len("comment1=cooking%20MCs;userdata=")
	padding := BlockSize - prefixLength%BlockSize
	if padding == BlockSize {
		padding = 0
	}

	x := make([]byte, padding+BlockSize)
	for i := 0; i < len(x); i++ {
		x[i] = 'A'
	}

	enc := encryptor(x)

	needed := ";admin=true;"
	have := ";comment2=%20like%20a%20pound%20of%20bacon"

	for i := padding + prefixLength; i < padding+prefixLength+len(needed); i++ {
		zeroIndex := i - padding - prefixLength
		enc[i] = needed[zeroIndex] ^ have[zeroIndex] ^ enc[i]
	}
	return checker(enc)
}
