package cryptopals

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
)

type AesCtr struct {
	cipher cipher.Block
	nonce  int64
}

func NewAesCtrCipher(key []byte, nonce int64) (cipher.Block, error) {
	if len(key) != BlockSize {
		return nil, errors.New("key size not 16")
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &AesCtr{cipher: cipher, nonce: nonce}, nil
}

func (a *AesCtr) BlockSize() int {
	return BlockSize
}

func (a *AesCtr) Encrypt(dst, src []byte) {
	var counter int64

	for counter = 0; counter <= int64(len(src)/BlockSize); counter++ {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, a.nonce)
		binary.Write(buf, binary.LittleEndian, counter)

		inter := make([]byte, BlockSize)
		a.cipher.Encrypt(inter, buf.Bytes())

		block := int(counter * BlockSize)
		for i := block; i < block+BlockSize; i++ {
			if i == len(src) {
				return
			}

			dst[i] = src[i] ^ inter[i%BlockSize]
		}
	}
}

func (a *AesCtr) Decrypt(dst, src []byte) {
	var counter int64

	for counter = 0; counter <= int64(len(src)/BlockSize); counter++ {
		buf := new(bytes.Buffer)
		binary.Write(buf, binary.LittleEndian, a.nonce)
		binary.Write(buf, binary.LittleEndian, counter)

		inter := make([]byte, BlockSize)
		a.cipher.Encrypt(inter, buf.Bytes())

		block := int(counter * BlockSize)
		for i := block; i < block+BlockSize; i++ {
			if i == len(src) {
				return
			}
			dst[i] = src[i] ^ inter[i%BlockSize]
		}
	}
}
