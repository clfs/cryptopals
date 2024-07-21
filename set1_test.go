package cryptopals

import (
	"bytes"
	"encoding/hex"
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
