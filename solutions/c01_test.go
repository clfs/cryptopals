package solutions

import (
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestChallenge01(t *testing.T) {
	in := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	want := "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

	raw, err := hex.DecodeString(in)
	if err != nil {
		t.Error(err)
	}
	got := base64.StdEncoding.EncodeToString(raw)

	if want != got {
		t.Errorf("want %q, got %q", want, got)
	}
}
