package cryptopals

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
