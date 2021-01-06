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
