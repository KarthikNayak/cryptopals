package cryptopals

import (
	"bufio"
	"bytes"
	"io/ioutil"
	"os"
	"strings"
	"testing"
)

func TestQ1(t *testing.T) {
	res, err := HexToB64([]byte("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"))
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

func TestQ3(t *testing.T) {
	key, _, s := SingleByteXorKey([]byte("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"))
	t.Log(s)
	if key != byte(88) {
		t.Fail()
	}
}

func TestQ4(t *testing.T) {
	file, err := os.Open("_data/4.txt")
	defer file.Close()
	if err != nil {
		t.Errorf("could not open file: %v", err)
	}

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	s := MultipleSingleByteXorKey(lines)
	if strings.Compare(s, "Now that the party is jumping\n") != 0 {
		t.Fail()
	}
}

func TestQ5(t *testing.T) {
	s := `Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal`

	result := RepeatingXor(s, "ICE")

	expected := `0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f`

	if strings.Compare(string(result), expected) != 0 {
		t.Errorf("expected :%s\ngot      :%s", string(result), expected)
	}
}

func TestHammingDistance(t *testing.T) {
	a := "this is a test"
	b := "wokka wokka!!!"
	dist := HammingDistance([]byte(a), []byte(b))
	if dist != 37 {
		t.Fail()
	}
}

func TestBreakIntoBlocks(t *testing.T) {
	d := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9}

	o := breakIntoBlocks(d, 2)
	if len(o) != 2 || len(o[0]) != 5 {
		t.Errorf("%#v", o)
	}

	o = breakIntoBlocks(d, 3)
	t.Log(o)
	if len(o) != 3 || len(o[0]) != 3 {
		t.Errorf("%#v", o)
	}

	o = breakIntoBlocks(d, 5)
	if len(o) != 5 || len(o[4]) != 1 {
		t.Errorf("%#v", o)
	}
}

func TestQ6(t *testing.T) {
	data, err := ioutil.ReadFile("_data/6.txt")
	if err != nil {
		t.Errorf("error opening file: %v", err)
	}

	key, err := BreakRepeatingXor(data)
	if err != nil {
		t.Errorf("got error: %v", err)
	}

	expected := "Terminator X: Bring the noise"

	if strings.Compare(string(key), expected) != 0 {
		t.Errorf("expected :%s\ngot      :%s", string(key), expected)
	}

}
