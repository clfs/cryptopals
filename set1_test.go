package cryptopals

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"os"
	"testing"
)

func TestChallenge1(t *testing.T) {
	in := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	want := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	got, err := hexToBase64(in)
	if err != nil {
		t.Error(err)
	}

	if want != got {
		t.Errorf("want %q, got %q", want, got)
	}
}

// decodeHex wraps hex.DecodeString for testing.
func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	data, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestChallenge2(t *testing.T) {
	a := decodeHex(t, "1c0111001f010100061a024b53535009181c")
	b := decodeHex(t, "686974207468652062756c6c277320657965")
	want := decodeHex(t, "746865206b696420646f6e277420706c6179")

	got := xor(a, b)
	if !bytes.Equal(want, got) {
		t.Errorf("want %q, got %q", want, got)
	}
}

func TestChallenge3(t *testing.T) {
	ct := decodeHex(t, "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
	want := byte(88)

	got := recoverSingleByteXORKey(ct)

	if want != got {
		t.Errorf("want %d, got %d", want, got)
	}

	singleByteXORCipher{key: got}.XORKeyStream(ct, ct)
	t.Logf("plaintext: %q", ct)
}

// decodeHexStringsFromFile decodes newline-delimited, hex-encoded strings from
// a file.
func decodeHexStringsFromFile(t *testing.T, name string) [][]byte {
	t.Helper()
	f, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	var res [][]byte

	s := bufio.NewScanner(f)
	for s.Scan() {
		data := decodeHex(t, s.Text())
		res = append(res, data)
	}

	if err := s.Err(); err != nil {
		t.Fatal(err)
	}

	return res
}

func TestChallenge4(t *testing.T) {
	in := decodeHexStringsFromFile(t, "testdata/4.txt")
	want := decodeHex(t, "7b5a4215415d544115415d5015455447414c155c46155f4058455c5b523f")

	got := findSingleByteXORCiphertext(in)

	if !bytes.Equal(want, got) {
		t.Errorf("want %x, got %x", want, got)
	}

	key := recoverSingleByteXORKey(got)
	singleByteXORCipher{key: key}.XORKeyStream(got, got)
	t.Logf("plaintext: %q", got)
}
