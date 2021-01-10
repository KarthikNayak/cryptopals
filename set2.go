package cryptopals

import (
	"bytes"
	"crypto/cipher"
	"math/rand"
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

	suffixSize := BlockSize - (len(src) % BlockSize)
	suffix := RandomText(suffixSize, suffixSize)
	src = append(src, suffix...)

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
