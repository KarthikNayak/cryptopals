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

func TestQ2(t *testing.T) {
	a := []byte("1c0111001f010100061a024b53535009181c")
	b := []byte("686974207468652062756c6c277320657965")

	c, err := Xor(a, b)
	if err != nil {
		t.Errorf("received error: %v", err)
	}

	req := []byte("746865206b696420646f6e277420706c6179")
	if bytes.Compare(c, req) != 0 {
		t.Errorf("value %v doesn't match: %v", c, req)
	}
}
