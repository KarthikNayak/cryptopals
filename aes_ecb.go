package cryptopals

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

type AesEcb128 struct {
	cipher cipher.Block
}

const BlockSize = 16

func NewAesEcb128Cipher(key []byte) (cipher.Block, error) {
	if len(key) != BlockSize {
		return nil, errors.New("key size not 16")
	}
	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &AesEcb128{cipher: cipher}, nil
}

func (a *AesEcb128) BlockSize() int {
	return BlockSize
}

func (a *AesEcb128) Encrypt(dst, src []byte) {
	for i := 0; i < len(src); i = i + 16 {
		tmp := make([]byte, 16)
		a.cipher.Encrypt(tmp, src[i:i+16])
		copy(dst[i:i+16], tmp)
	}
}

func (a *AesEcb128) Decrypt(dst, src []byte) {
	for i := 0; i < len(src); i = i + 16 {
		tmp := make([]byte, 16)
		a.cipher.Decrypt(tmp, src[i:i+16])
		copy(dst[i:i+16], tmp)
	}
}
