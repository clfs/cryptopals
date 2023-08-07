package solutions

import (
	"bytes"
	"encoding/hex"
	"testing"

	"github.com/clfs/cryptopals"
)

func hexDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestChallenge02(t *testing.T) {
	a := hexDecode(t, "1c0111001f010100061a024b53535009181c")
	b := hexDecode(t, "686974207468652062756c6c277320657965")
	want := hexDecode(t, "746865206b696420646f6e277420706c6179")

	got := cryptopals.XOR(a, b)
	if !bytes.Equal(want, got) {
		t.Errorf("want %q, got %q", want, got)
	}
}
