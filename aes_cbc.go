package cryptopals

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
)

type AesCbc128 struct {
	cipher cipher.Block
	IV     []byte
}

func NewAesCbc128Cipher(key []byte, IV []byte) (cipher.Block, error) {
	if len(key) != BlockSize {
		return nil, errors.New("key size not 16")
	}
	if len(IV) != BlockSize {
		return nil, errors.New("IV size not 16")
	}

	cipher, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	return &AesCbc128{cipher: cipher, IV: IV}, nil
}

func (a *AesCbc128) BlockSize() int {
	return BlockSize
}

func (a *AesCbc128) Encrypt(dst, src []byte) {
	iv := make([]byte, 16)
	copy(iv, a.IV)

	for i := 0; i < len(src); i = i + 16 {
		for j := 0; j < 16; j++ {
			iv[j] = src[i+j] ^ iv[j]
		}

		a.cipher.Encrypt(iv, iv)
		copy(dst[i:i+16], iv)
	}
}

func (a *AesCbc128) Decrypt(dst, src []byte) {
	iv := make([]byte, 16)
	copy(iv, a.IV)

	for i := 0; i < len(src); i = i + 16 {
		tmp := make([]byte, 16)
		a.cipher.Decrypt(tmp, src[i:i+16])
		copy(dst[i:i+16], tmp)

		for j := 0; j < 16; j++ {
			dst[i+j] = dst[i+j] ^ iv[j]
		}
		copy(iv, src[i:i+16])
	}
}
