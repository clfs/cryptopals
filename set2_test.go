package cryptopals

import (
	"bytes"
	"testing"
)

func TestChallenge10(t *testing.T) {
	in := []byte("YELLOW SUBMARINE")
	n := 20
	want := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")

	got := pkcs7pad(in, n)
	if !bytes.Equal(want, got) {
		t.Errorf("want %q, got %q", want, got)
	}
}
