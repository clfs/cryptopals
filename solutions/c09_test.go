package solutions

import (
	"bytes"
	"testing"

	"github.com/clfs/cryptopals/pkcs7"
)

func TestChallenge09(t *testing.T) {
	in := []byte("YELLOW SUBMARINE")
	blockSize := 20
	want := []byte("YELLOW SUBMARINE\x04\x04\x04\x04")

	got := pkcs7.Pad(in, blockSize)
	if !bytes.Equal(want, got) {
		t.Errorf("want %x, got %x", want, got)
	}
}
