package cryptopals

import (
	"bytes"
	"testing"
)

func TestQ1(t *testing.T) {
	res, err := hexToB64([]byte("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
	if err != nil {
		t.Errorf("received error: %v", err)
	}

	if bytes.Compare(res, []byte("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")) != 0 {
		t.Errorf("value doesn't match: %v", res)
	}
}
